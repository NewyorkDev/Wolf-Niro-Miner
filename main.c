#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#include <jansson.h>
#include <sys/time.h>
#include <stdatomic.h>
#include <CL/cl.h>

#ifdef __linux__

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sched.h>
#include <fcntl.h>

#else

#include <winsock2.h>

#endif

#include "minerutils.h"
#include "minerlog.h"
#include "minernet.h"
#include "miner.h"
#include "ocl.h"

#define OLD_ROUND		205
#define NEW_ROUND		204
#define BLOCK_ACCEPTED	200
#define BLOCK_REJECTED	201
#define GET_ROUND		133
#define GET_HEIGHT 		130
#define GET_BLOCK 		129
#define SET_CHANNEL 	3
#define BLOCK_HEIGHT	2
#define SUBMIT_BLOCK	1
#define BLOCK_DATA		0

typedef struct _JobInfo
{
	uint32_t Height;
	uint8_t *BlockBlob;
	bool Initialized;
} JobInfo;

typedef struct _StatusInfo
{
	uint64_t SolvedWork;
	uint64_t RejectedWork;
	double *ThreadHashCounts;
	double *ThreadTimes;
} StatusInfo;

pthread_mutex_t StatusMutex = PTHREAD_MUTEX_INITIALIZER;
StatusInfo GlobalStatus;

#pragma pack(push, 1)

// Note that the merkle root is the ONLY thing we don't byteswap.

typedef struct _BlockHeader
{
	uint32_t Version;
	uint8_t PrevHash[32];
	uint8_t MerkleRoot[32];
	uint32_t Time;
	uint32_t NetworkDiff;
	uint32_t Nonce;
	uint32_t Padding[12];
} BlockHeader;

#pragma pack(pop)

typedef struct _Work
{
	char *ID;
	uint8_t *Data;
	uint8_t *FullTarget;
	uint32_t Nonce;
	uint32_t Extranonce2;		// Assumes extranonce2 size is 4 or less
	uint32_t nTime;
	struct _Work *next;
} Work;

typedef struct _WorkQueue
{
	Work *first;
	Work *last;
} WorkQueue;

typedef struct _WorkerInfo
{
	char *User;
	char *Pass;
	struct _WorkerInfo *NextWorker;
} WorkerInfo;

typedef struct _PoolInfo
{
	int sockfd;
	char *PoolName;
	WorkerInfo WorkerData;
	uint32_t MinerThreadCount;
	uint32_t *MinerThreads;
	atomic_uint_least32_t StratumID;
} PoolInfo;

typedef struct _LLPPacket
{
	uint8_t Header;
	uint32_t Length;
	uint8_t *Data;
} LLPPacket;

pthread_mutex_t GlobalWorkMutex = PTHREAD_MUTEX_INITIALIZER;
WorkQueue GlobalWorkQueue = { NULL, NULL };

void PushWork(WorkQueue *queue, Work *NewWork)
{
	NewWork->next = NULL;
	
	if(!queue->first) queue->first = queue->last = NewWork;
	else queue->last = queue->last->next = NewWork;
}

Work *PopWork(WorkQueue *queue)
{
	Work *tmp = queue->first;
	if(queue->first) queue->first = queue->first->next;	
	return(tmp);
}

Work *PeekWork(WorkQueue *queue)
{
	return(queue->first);
}

void FreeWork(Work *WorkItem)
{
	free(WorkItem->ID);
	free(WorkItem->Data);
	free(WorkItem->FullTarget);
	free(WorkItem);
}

void FlushWorkQueue(WorkQueue *queue)
{
	Work *TmpWork;
	
	while(TmpWork = PopWork(queue)) FreeWork(TmpWork);
}

atomic_bool *RestartMining;

pthread_mutex_t Mutex = PTHREAD_MUTEX_INITIALIZER;
bool ExitFlag = false;

pthread_mutex_t JobMutex = PTHREAD_MUTEX_INITIALIZER;
JobInfo CurrentJob;

typedef struct _Share
{
	uint64_t Nonce;
	uint8_t MerkleRoot[64];
	struct _Share *next;
} Share;

typedef struct _ShareQueue
{
	Share *first;
	Share *last;
} ShareQueue;

void SubmitShare(ShareQueue *queue, Share *NewShare)
{
	NewShare->next = NULL;
	
	if(!queue->first) queue->first = queue->last = NewShare;
	else queue->last = queue->last->next = NewShare;
}

Share *RemoveShare(ShareQueue *queue)
{
	Share *tmp = queue->first;
	if(queue->first) queue->first = queue->first->next;	
	return(tmp);
}

void FreeShare(Share *share)
{
	free(share);
}

ShareQueue CurrentQueue;
pthread_mutex_t QueueMutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct _PoolBroadcastInfo
{
	int poolsocket;
	WorkerInfo WorkerData;
} PoolBroadcastInfo;

// TODO/FIXME: Check for error - and sanity check the length
int32_t GetLLPPacket(LLPPacket *Packet, PoolInfo *Pool)
{
	int ret;
	uint8_t Metadata[5];
	
	ret = recv(Pool->sockfd, Metadata, 1, 0);
	// TODO/FIXME: Check for EAGAIN/EWOULDBLOCK, closed connection,
	// and real error conditions, and handle accordingly.
	if(ret < 0) return(-1);
	
	Packet->Header = Metadata[0];
	
	if(Packet->Header < 128)
	{
		ret = recv(Pool->sockfd, Metadata, 4, 0);
		
		Packet->Length = __builtin_bswap32(((uint32_t *)(Metadata + 1))[0]);
		Packet->Data = (uint8_t *)malloc(sizeof(uint8_t) * Packet->Length);
		
		// TODO/FIXME: Loop this, checking to ensure we got the whole packet
		// before we stop reading
		ret = recv(Pool->sockfd, Packet->Data, Packet->Length, 0);
		
		// All packets should have a length that is a multiple of 4
		// TODO/FIXME: Double check length IS a multiple of 4
		for(int i = 0; i < (Packet->Length >> 2); ++i) ((uint32_t *)Packet->Data)[i] = __builtin_bswap32(((uint32_t *)Packet->Data)[i]);
	}
	
	return(0);
}

// TODO/FIXME: Check for error
void SendLLPPacket(LLPPacket *Packet, PoolInfo *Pool)
{
	int ret;
	uint8_t Metadata[5];
	
	Metadata[0] = Packet->Header;
	((uint32_t *)(Metadata + 1))[0] = __builtin_bswap32(Packet->Length);
	
	if(Packet->Length)
	{	
		ret = send(Pool->sockfd, Metadata, 5, 0);
		
		// All packets should have a length that is a multiple of 4
		for(int i = 0; i < (Packet->Length >> 2); ++i) ((uint32_t *)Packet->Data)[i] = __builtin_bswap32(((uint32_t *)Packet->Data)[i]);
		
		// TODO/FIXME: Loop this, checking to ensure we sent the whole packet
		ret = send(Pool->sockfd, Packet->Data, Packet->Length, 0);
	}
	else
	{
		ret = send(Pool->sockfd, Metadata, 1, 0);
	}
}

// WARNING/TODO/FIXME: ID needs to be a global counter with atomic accesses
// TODO/FIXME: Check various calls for error
void *PoolBroadcastThreadProc(void *Info)
{
	uint64_t id = 10;
	PoolInfo *pbinfo = (PoolInfo *)Info;
	pthread_mutex_lock(&QueueMutex);
	CurrentQueue.first = CurrentQueue.last = NULL;
	pthread_mutex_unlock(&QueueMutex);
	
	// TODO/FIXME: Process ALL shares in the queue at a time
	// TODO/FIXME: Get nonce, release queue, only lock queue to
	// get more winning nonces.
	for(;;)
	{
		// TODO/FIXME: Use nanosleep().
		while(pthread_mutex_trylock(&QueueMutex)) sleep(1);
		for(Share *CurShare = RemoveShare(&CurrentQueue); CurShare; CurShare = RemoveShare(&CurrentQueue))
		{
			LLPPacket Req, Resp;
			uint64_t buf[9];
			
			memcpy(buf, CurShare->MerkleRoot, 64);
			buf[8] = CurShare->Nonce;
			
			Req.Header = SUBMIT_BLOCK;
			Req.Length = 72UL;
			Req.Data = (uint8_t *)buf;
			
			SendLLPPacket(&Req, pbinfo);
						
			pthread_mutex_lock(&StatusMutex);
			GlobalStatus.SolvedWork++;
			pthread_mutex_unlock(&StatusMutex);
			
			FreeShare(CurShare);		
		}
		pthread_mutex_unlock(&QueueMutex);
	}
	return(NULL);
}

void SetChannel(PoolInfo *Pool, uint32_t Channel)
{
	LLPPacket Request, Response;
		
	Request.Header = SET_CHANNEL;
	Request.Length = 4U;
	Request.Data = &Channel;
	
	SendLLPPacket(&Request, Pool);
}
	
void *LLPThreadProc(void *InfoPtr)
{
	PoolInfo *Pool = (PoolInfo *)InfoPtr;
	LLPPacket Incoming, Outgoing;
	TIME_TYPE LastCheckTime;
	
	SetNonBlockingSocket(Pool->sockfd);
	
	SetChannel(Pool, 2U);
	
	Outgoing.Header = GET_ROUND;
	Outgoing.Length = 0U;
	Outgoing.Data = NULL;
	
	SendLLPPacket(&Outgoing, Pool);
	LastCheckTime = MinerGetCurTime();
	
	for(;;)
	{
		// If there's a packet to process, do so.
		if(GetLLPPacket(&Incoming, Pool) >= 0)
		{
			switch(Incoming.Header)
			{
				case NEW_ROUND:
				{
					Outgoing.Header = GET_BLOCK;
					Outgoing.Length = 0U;
					Outgoing.Data = NULL;
					
					SendLLPPacket(&Outgoing, Pool);
					
					break;
				}
				case OLD_ROUND:
				{
					break;
				}
				case BLOCK_DATA:
				{
					pthread_mutex_lock(&JobMutex);
					
					if(CurrentJob.Initialized) free(CurrentJob.BlockBlob);
					
					CurrentJob.BlockBlob = Incoming.Data;
					
					printf("New block on network.\n");
					
					CurrentJob.Initialized = true;
					
					// Remember, we only get this packet when we needed initial
					// work, or becaus height changed and we needed updates.
					for(int i = 0; i < Pool->MinerThreadCount; ++i)
						atomic_store(RestartMining + i, true);
					
					pthread_mutex_unlock(&JobMutex);
					break;
				}
				case BLOCK_ACCEPTED:
				{
					pthread_mutex_lock(&StatusMutex);
					
					Log(LOG_INFO, "Block accepted: %d/%d (%.02f%%)", GlobalStatus.SolvedWork - GlobalStatus.RejectedWork, GlobalStatus.SolvedWork, (double)(GlobalStatus.SolvedWork - GlobalStatus.RejectedWork) / GlobalStatus.SolvedWork * 100.0);
					
					pthread_mutex_unlock(&StatusMutex);
					break;
				}
				case BLOCK_REJECTED:
				{
					pthread_mutex_lock(&StatusMutex);
					
					GlobalStatus.RejectedWork++;
					Log(LOG_INFO, "Block rejected: %d/%d (%.02f%%)", GlobalStatus.SolvedWork - GlobalStatus.RejectedWork, GlobalStatus.SolvedWork, (double)(GlobalStatus.SolvedWork - GlobalStatus.RejectedWork) / GlobalStatus.SolvedWork * 100.0);
					
					pthread_mutex_unlock(&StatusMutex);
					break;
				}
			}
		}
		
		if(SecondsElapsed(LastCheckTime, MinerGetCurTime()) >= 3.0)
		{
			Outgoing.Header = GET_ROUND;
			Outgoing.Length = 0U;
			Outgoing.Data = NULL;
			
			SendLLPPacket(&Outgoing, Pool);
			
			LastCheckTime = MinerGetCurTime();
		}
	}
	
	return(NULL);
}

int32_t SetupNiroMiner(AlgoContext *HashData, OCLPlatform *OCL, uint32_t DeviceIdx)
{
	size_t len;
	cl_int retval;
	char *KernelSource, *BuildLog, *Options;
	size_t GlobalThreads = OCL->Devices[DeviceIdx].xIntensity * OCL->Devices[DeviceIdx].TotalShaders, LocalThreads = OCL->Devices[DeviceIdx].WorkSize;
	const cl_queue_properties CommandQueueProperties[] = { 0, 0, 0 };
	
	// Sanity checks
	if(!HashData || !OCL) return(ERR_STUPID_PARAMS);
	
	HashData->GlobalSize = GlobalThreads;
	HashData->WorkSize = LocalThreads;
	
	HashData->CommandQueues = (cl_command_queue *)malloc(sizeof(cl_command_queue));
	
	*HashData->CommandQueues = clCreateCommandQueueWithProperties(OCL->Context, OCL->Devices[DeviceIdx].DeviceID, CommandQueueProperties, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateCommandQueueWithProperties.", retval);
		return(ERR_OCL_API);
	}
	
	// One extra buffer for the midstate is required, and one for the high nonce
	HashData->ExtraBuffers = (cl_mem *)malloc(sizeof(cl_mem) * 2);
	
	HashData->InputBuffer = clCreateBuffer(OCL->Context, CL_MEM_READ_ONLY, sizeof(cl_ulong) * 26, NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateBuffer to create input buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// Midstate
	HashData->ExtraBuffers[0] = clCreateBuffer(OCL->Context, CL_MEM_READ_WRITE, sizeof(cl_ulong) * 17, NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateBuffer to create midstate buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// High nonce
	HashData->ExtraBuffers[1] = clCreateBuffer(OCL->Context, CL_MEM_READ_WRITE, sizeof(cl_ulong), NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateBuffer to create midstate buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// Output
	// Assume we may find up to 0xFF nonces in one run - it's reasonable
	HashData->OutputBuffer = clCreateBuffer(OCL->Context, CL_MEM_READ_WRITE, sizeof(cl_ulong) * 0x100, NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateBuffer to create output buffer.", retval);
		return(ERR_OCL_API);
	}
	
	len = LoadTextFile(&KernelSource, "sk1024.cl");
	
	HashData->Program = clCreateProgramWithSource(OCL->Context, 1, (const char **)&KernelSource, NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateProgramWithSource on the contents of %s.", retval, "sk1024.cl");
		return(ERR_OCL_API);
	}
		
	Options = (char *)malloc(sizeof(char) * 32);
	
	snprintf(Options, 31, "-I. -DWORKSIZE=%d", LocalThreads);
	
	retval = clBuildProgram(HashData->Program, 1, &OCL->Devices[DeviceIdx].DeviceID, Options, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clBuildProgram.", retval);
		
		retval = clGetProgramBuildInfo(HashData->Program, OCL->Devices[DeviceIdx].DeviceID, CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
	
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clGetProgramBuildInfo for length of build log output.", retval);
			return(ERR_OCL_API);
		}
		
		BuildLog = (char *)malloc(sizeof(char) * (len + 2));
		
		retval = clGetProgramBuildInfo(HashData->Program, OCL->Devices[DeviceIdx].DeviceID, CL_PROGRAM_BUILD_LOG, len, BuildLog, NULL);
		
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clGetProgramBuildInfo for build log.", retval);
			return(ERR_OCL_API);
		}
		
		Log(LOG_CRITICAL, "Build Log:\n%s", BuildLog);
		
		free(BuildLog);
		
		return(ERR_OCL_API);
	}
	
	cl_build_status status;
	
	do
	{
		retval = clGetProgramBuildInfo(HashData->Program, OCL->Devices[DeviceIdx].DeviceID, CL_PROGRAM_BUILD_STATUS, sizeof(cl_build_status), &status, NULL);
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clGetProgramBuildInfo for status of build.", retval);
			return(ERR_OCL_API);
		}
		
		sleep(1);
	} while(status == CL_BUILD_IN_PROGRESS);
	
	retval = clGetProgramBuildInfo(HashData->Program, OCL->Devices[DeviceIdx].DeviceID, CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clGetProgramBuildInfo for length of build log output.", retval);
		return(ERR_OCL_API);
	}
	
	BuildLog = (char *)malloc(sizeof(char) * (len + 2));
	
	retval = clGetProgramBuildInfo(HashData->Program, OCL->Devices[DeviceIdx].DeviceID, CL_PROGRAM_BUILD_LOG, len, BuildLog, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clGetProgramBuildInfo for build log.", retval);
		return(ERR_OCL_API);
	}
	
	Log(LOG_DEBUG, "Build Log:\n%s", BuildLog);
	
	free(BuildLog);
	free(KernelSource);
	
	// Only one kernel
	HashData->Kernels = (cl_kernel *)malloc(sizeof(cl_kernel));
	
	*HashData->Kernels = clCreateKernel(HashData->Program, "sk1024", &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateKernel for kernel %s.", retval, "sk1024");
		return(ERR_OCL_API);
	}
	
	HashData->Nonce = 0;
	
	// Hardcode one GPU per thread in this version
	HashData->GPUIdxs = (size_t *)malloc(sizeof(size_t));
	*HashData->GPUIdxs = DeviceIdx;
	
	return(ERR_SUCCESS);
}

#define ROL64(x, y)		(((x) << (y)) | ((x) >> (64 - (y))))

static void Round1024_host(uint64_t *p0, uint64_t *p1, uint64_t *p2, uint64_t *p3, uint64_t *p4, uint64_t *p5, uint64_t *p6, uint64_t *p7,
	uint64_t *p8, uint64_t *p9, uint64_t *pA, uint64_t *pB, uint64_t *pC, uint64_t *pD, uint64_t *pE, uint64_t *pF, int ROT)
{

	static const int cpu_ROT1024[8][8] =
	{
		{ 55, 43, 37, 40, 16, 22, 38, 12 },
		{ 25, 25, 46, 13, 14, 13, 52, 57 },
		{ 33, 8, 18, 57, 21, 12, 32, 54 },
		{ 34, 43, 25, 60, 44, 9, 59, 34 },
		{ 28, 7, 47, 48, 51, 9, 35, 41 },
		{ 17, 6, 18, 25, 43, 42, 40, 15 },
		{ 58, 7, 32, 45, 19, 18, 2, 56 },
		{ 47, 49, 27, 58, 37, 48, 53, 56 }
	};



	*p0 += *p1;
	*p1 = ROL64(*p1, cpu_ROT1024[ROT][0]);
	*p1 ^= *p0;
	*p2 += *p3;
	*p3 = ROL64(*p3, cpu_ROT1024[ROT][1]);
	*p3 ^= *p2;
	*p4 += *p5;
	*p5 = ROL64(*p5, cpu_ROT1024[ROT][2]);
	*p5 ^= *p4;
	*p6 += *p7;
	*p7 = ROL64(*p7, cpu_ROT1024[ROT][3]);
	*p7 ^= *p6;
	*p8 += *p9;
	*p9 = ROL64(*p9, cpu_ROT1024[ROT][4]);
	*p9 ^= *p8;
	*pA += *pB;
	*pB = ROL64(*pB, cpu_ROT1024[ROT][5]);
	*pB ^= *pA;
	*pC += *pD;
	*pD = ROL64(*pD, cpu_ROT1024[ROT][6]);
	*pD ^= *pC;
	*pE += *pF;
	*pF = ROL64(*pF, cpu_ROT1024[ROT][7]);
	*pF ^= *pE;
}

void SkeinFirstRound(unsigned int *pData, unsigned long long* skeinC)
{
/// first round of skein performed on cpu ==> constant on gpu

	static const uint64_t cpu_SKEIN1024_IV_1024[16] =
	{
		//     lo           hi
		0x5A4352BE62092156,
		0x5F6E8B1A72F001CA,
		0xFFCBFE9CA1A2CE26,
		0x6C23C39667038BCA,
		0x583A8BFCCE34EB6C,
		0x3FDBFB11D4A46A3E,
		0x3304ACFCA8300998,
		0xB2F6675FA17F0FD2,
		0x9D2599730EF7AB6B,
		0x0914A20D3DFEA9E4,
		0xCC1A9CAFA494DBD3,
		0x9828030DA0A6388C,
		0x0D339D5DAADEE3DC,
		0xFC46DE35C4E2A086,
		0x53D6E4F52E19A6D1,
		0x5663952F715D1DDD,
	};
	
	uint64_t t[3];
	uint64_t h[17];
	uint64_t p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15;

	uint64_t cpu_skein_ks_parity = 0x5555555555555555;
	h[16] = cpu_skein_ks_parity;
	for (int i = 0; i<16; i++) {
		h[i] = cpu_SKEIN1024_IV_1024[i];
		h[16] ^= h[i];
	}
	uint64_t* alt_data = (uint64_t*)pData;
	/////////////////////// round 1 //////////////////////////// should be on cpu => constant on gpu
	p0 = alt_data[0];
	p1 = alt_data[1];
	p2 = alt_data[2];
	p3 = alt_data[3];
	p4 = alt_data[4];
	p5 = alt_data[5];
	p6 = alt_data[6];
	p7 = alt_data[7];
	p8 = alt_data[8];
	p9 = alt_data[9];
	p10 = alt_data[10];
	p11 = alt_data[11];
	p12 = alt_data[12];
	p13 = alt_data[13];
	p14 = alt_data[14];
	p15 = alt_data[15];
	t[0] = 0x80; // ptr  
	t[1] = 0x7000000000000000; // etype
	t[2] = 0x7000000000000080;

	p0 += h[0];
	p1 += h[1];
	p2 += h[2];
	p3 += h[3];
	p4 += h[4];
	p5 += h[5];
	p6 += h[6];
	p7 += h[7];
	p8 += h[8];
	p9 += h[9];
	p10 += h[10];
	p11 += h[11];
	p12 += h[12];
	p13 += h[13] + t[0];
	p14 += h[14] + t[1];
	p15 += h[15];

	for (int i = 1; i < 21; i += 2)
	{

		Round1024_host(&p0, &p1, &p2, &p3, &p4, &p5, &p6, &p7, &p8, &p9, &p10, &p11, &p12, &p13, &p14, &p15, 0);
		Round1024_host(&p0, &p9, &p2, &p13, &p6, &p11, &p4, &p15, &p10, &p7, &p12, &p3, &p14, &p5, &p8, &p1, 1);
		Round1024_host(&p0, &p7, &p2, &p5, &p4, &p3, &p6, &p1, &p12, &p15, &p14, &p13, &p8, &p11, &p10, &p9, 2);
		Round1024_host(&p0, &p15, &p2, &p11, &p6, &p13, &p4, &p9, &p14, &p1, &p8, &p5, &p10, &p3, &p12, &p7, 3);

		p0 += h[(i + 0) % 17];
		p1 += h[(i + 1) % 17];
		p2 += h[(i + 2) % 17];
		p3 += h[(i + 3) % 17];
		p4 += h[(i + 4) % 17];
		p5 += h[(i + 5) % 17];
		p6 += h[(i + 6) % 17];
		p7 += h[(i + 7) % 17];
		p8 += h[(i + 8) % 17];
		p9 += h[(i + 9) % 17];
		p10 += h[(i + 10) % 17];
		p11 += h[(i + 11) % 17];
		p12 += h[(i + 12) % 17];
		p13 += h[(i + 13) % 17] + t[(i + 0) % 3];
		p14 += h[(i + 14) % 17] + t[(i + 1) % 3];
		p15 += h[(i + 15) % 17] + (uint64_t)i;

		Round1024_host(&p0, &p1, &p2, &p3, &p4, &p5, &p6, &p7, &p8, &p9, &p10, &p11, &p12, &p13, &p14, &p15, 4);
		Round1024_host(&p0, &p9, &p2, &p13, &p6, &p11, &p4, &p15, &p10, &p7, &p12, &p3, &p14, &p5, &p8, &p1, 5);
		Round1024_host(&p0, &p7, &p2, &p5, &p4, &p3, &p6, &p1, &p12, &p15, &p14, &p13, &p8, &p11, &p10, &p9, 6);
		Round1024_host(&p0, &p15, &p2, &p11, &p6, &p13, &p4, &p9, &p14, &p1, &p8, &p5, &p10, &p3, &p12, &p7, 7);

		p0 += h[(i + 1) % 17];
		p1 += h[(i + 2) % 17];
		p2 += h[(i + 3) % 17];
		p3 += h[(i + 4) % 17];
		p4 += h[(i + 5) % 17];
		p5 += h[(i + 6) % 17];
		p6 += h[(i + 7) % 17];
		p7 += h[(i + 8) % 17];
		p8 += h[(i + 9) % 17];
		p9 += h[(i + 10) % 17];
		p10 += h[(i + 11) % 17];
		p11 += h[(i + 12) % 17];
		p12 += h[(i + 13) % 17];
		p13 += h[(i + 14) % 17] + t[(i + 1) % 3];
		p14 += h[(i + 15) % 17] + t[(i + 2) % 3];
		p15 += h[(i + 16) % 17] + (uint64_t)(i + 1);


	}

	h[0] = p0^alt_data[0];
	h[1] = p1^alt_data[1];
	h[2] = p2^alt_data[2];
	h[3] = p3^alt_data[3];
	h[4] = p4^alt_data[4];
	h[5] = p5^alt_data[5];
	h[6] = p6^alt_data[6];
	h[7] = p7^alt_data[7];
	h[8] = p8^alt_data[8];
	h[9] = p9^alt_data[9];
	h[10] = p10^alt_data[10];
	h[11] = p11^alt_data[11];
	h[12] = p12^alt_data[12];
	h[13] = p13^alt_data[13];
	h[14] = p14^alt_data[14];
	h[15] = p15^alt_data[15];
	h[16] = cpu_skein_ks_parity;
	for (int i = 0; i<16; i++) { h[16] ^= h[i]; }


	memcpy(skeinC, h, sizeof(unsigned long long) * 17);
}
int32_t NiroSetKernelArgs(AlgoContext *HashData, void *HashInput, uint64_t Target)
{
	cl_int retval;
	cl_ulong temp;
	cl_ulong Midstate[17];
	cl_uint zero = 0, fuckingcompiler = 24;
	size_t GlobalThreads = HashData->GlobalSize, LocalThreads = HashData->WorkSize;
	
	if(!HashData || !HashInput) return(ERR_STUPID_PARAMS);
	
	retval = clEnqueueWriteBuffer(*HashData->CommandQueues, HashData->InputBuffer, CL_TRUE, 0, 26 * sizeof(cl_ulong), HashInput, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueWriteBuffer to fill input buffer.", retval);
		return(ERR_OCL_API);
	}
	
	SkeinFirstRound(HashInput, Midstate);
	
	retval = clEnqueueWriteBuffer(*HashData->CommandQueues, HashData->ExtraBuffers[0], CL_TRUE, 0, 17 * sizeof(cl_ulong), Midstate, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueWriteBuffer to fill midstate buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// Input buffer
	retval = clSetKernelArg(HashData->Kernels[0], 0, sizeof(cl_mem), &HashData->InputBuffer);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for input buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// Midstate
	retval = clSetKernelArg(HashData->Kernels[0], 1, sizeof(cl_mem), HashData->ExtraBuffers);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for midstate buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// High 32-bits of nonce
	retval = clSetKernelArg(HashData->Kernels[0], 2, sizeof(cl_mem), HashData->ExtraBuffers + 1);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for midstate buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// Output buffer
	retval = clSetKernelArg(HashData->Kernels[0], 3, sizeof(cl_mem), &HashData->OutputBuffer);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for output buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// Compiler fuckup fix
	retval = clSetKernelArg(HashData->Kernels[0], 4, sizeof(cl_uint), &fuckingcompiler);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for target.", retval);
		return(ERR_OCL_API);
	}
	
	// Target
	retval = clSetKernelArg(HashData->Kernels[0], 5, sizeof(cl_ulong), &Target);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for target.", retval);
		return(ERR_OCL_API);
	}
	
	return(ERR_SUCCESS);
}

int32_t RunNiroKernel(AlgoContext *HashData, void *HashOutput)
{
	cl_int retval;
	cl_ulong zero = 0, HighNonce = HashData->Nonce & 0xFFFFFFFF00000000ULL;
	size_t GlobalThreads = HashData->GlobalSize, LocalThreads = HashData->WorkSize;
	
	if(!HashData || !HashOutput) return(ERR_STUPID_PARAMS);
	
	retval = clEnqueueWriteBuffer(*HashData->CommandQueues, HashData->OutputBuffer, CL_TRUE, sizeof(cl_ulong) * 0xFF, sizeof(cl_ulong), &zero, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueWriteBuffer to zero result counter.", retval);
		return(ERR_OCL_API);
	}
	
	// NOTE: This is very slightly wasteful, as the high 32 bits of the
	// nonce are obviously not updated after every kernel execution.
	retval = clEnqueueWriteBuffer(*HashData->CommandQueues, HashData->ExtraBuffers[1], CL_TRUE, 0, sizeof(cl_ulong), &HighNonce, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueWriteBuffer to set high 32 bits of the nonce.", retval);
		return(ERR_OCL_API);
	}
	
	retval = clEnqueueNDRangeKernel(*HashData->CommandQueues, HashData->Kernels[0], 1, &HashData->Nonce, &GlobalThreads, &LocalThreads, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueNDRangeKernel for kernel.", retval);
		return(ERR_OCL_API);
	}
	
	retval = clEnqueueReadBuffer(*HashData->CommandQueues, HashData->OutputBuffer, CL_TRUE, 0, sizeof(cl_ulong) * 0x100, HashOutput, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueReadBuffer to fetch results.", retval);
		return(ERR_OCL_API);
	}
	
	clFinish(*HashData->CommandQueues);
	
	HashData->Nonce += GlobalThreads;
	
	return(ERR_SUCCESS);
}

// AlgoName must not be freed by the thread - cleanup is done by caller.
// RequestedWorksize and RequestedxIntensity should be zero if none was requested
typedef struct _MinerThreadInfo
{
	uint32_t RequestedWorksize;
	uint32_t RequestedxIntensity;
	uint32_t ThreadID;
	uint32_t TotalMinerThreads;
	OCLPlatform *PlatformContext;
	AlgoContext AlgoCtx;
} MinerThreadInfo;

void *MinerThreadProc(void *Info)
{
	int32_t err;
	uint64_t TmpWork[26];
	uint64_t FullTarget[16] = { 0 };
	MinerThreadInfo *MTInfo = (MinerThreadInfo *)Info;
	uint64_t StartNonce = (0xFFFFFFFFFFFFFFFFULL / (uint64_t)MTInfo->TotalMinerThreads) * (uint64_t)MTInfo->ThreadID;
	uint64_t MaxNonce = (0xFFFFFFFFFFFFFFFFULL / (uint64_t)MTInfo->TotalMinerThreads) * (uint64_t)(MTInfo->ThreadID + 1);
	uint64_t Nonce = StartNonce, PrevNonce;
	
	Log(LOG_DEBUG, "TotalMinerThreads = %d.", MTInfo->TotalMinerThreads);
	
	while(!ExitFlag)
	{
		TIME_TYPE begin, end;
		
		//atomic_store(RestartMining + MTInfo->ThreadID, false);
		pthread_mutex_lock(&JobMutex);
		
		if(MTInfo->AlgoCtx.Nonce >= MaxNonce || atomic_load(RestartMining + MTInfo->ThreadID))
		{
			if(MTInfo->AlgoCtx.Nonce >= MaxNonce)
				Log(LOG_DEBUG, "Thread %d: Ran out of nonces, regenerating work.", MTInfo->ThreadID);
			
			if(atomic_load(RestartMining + MTInfo->ThreadID))
				Log(LOG_DEBUG, "Thread %d: Signaled to reload work.", MTInfo->ThreadID);
			
			atomic_store(RestartMining + MTInfo->ThreadID, false);
			
			uint32_t bits = ((uint32_t *)CurrentJob.BlockBlob)[51];
			uint8_t size = (unsigned char)(bits >> 24);
			
			for(int i = 0; i < 26; ++i) TmpWork[i] = ((uint64_t *)CurrentJob.BlockBlob)[i];
						
			pthread_mutex_unlock(&JobMutex);
			
			// Fill the target backwards
			if(size >= 1) ((uint8_t *)FullTarget)[127 - 4] = (bits >> 16) & 0xFF;
			if(size >= 2) ((uint8_t *)FullTarget)[127 - 5] = (bits >> 8) & 0xFF;
			if(size >= 3) ((uint8_t *)FullTarget)[127 - 6] = bits & 0xFF;
			
			Log(LOG_DEBUG, "nSize: %d.", size);
						
			Log(LOG_DEBUG, "Target: 0x%016llX\n", ((uint64_t *)FullTarget)[15]);
			
			MTInfo->AlgoCtx.Nonce = StartNonce;
			
			Log(LOG_DEBUG, "Thread %d: Scanning nonce range 0x%016llX - 0x%016llX.", MTInfo->ThreadID, StartNonce, MaxNonce);
			
			err = NiroSetKernelArgs(&MTInfo->AlgoCtx, TmpWork, ((uint64_t *)FullTarget)[15]);
			if(err) return(NULL);
		}
		else
		{
			pthread_mutex_unlock(&JobMutex);
		}
		
		PrevNonce = MTInfo->AlgoCtx.Nonce;
				
		begin = MinerGetCurTime();
		
		do
		{
			cl_ulong Results[0x100] = { 0 };
			
			err = RunNiroKernel(&MTInfo->AlgoCtx, Results);
			if(err) return(NULL);
			
			if(atomic_load(RestartMining + MTInfo->ThreadID)) break;
			
			for(int i = 0; i < Results[0xFF]; ++i)
			{
				Log(LOG_DEBUG, "Thread %d, GPU ID %d, GPU Type: %s: SHARE found (nonce 0x%016llX)!", MTInfo->ThreadID, *MTInfo->AlgoCtx.GPUIdxs, MTInfo->PlatformContext->Devices[*MTInfo->AlgoCtx.GPUIdxs].DeviceName, Results[i]);
				
				Share *NewShare = (Share *)malloc(sizeof(Share));
				
				NewShare->Nonce = Results[i];
				memcpy(NewShare->MerkleRoot, ((uint8_t *)TmpWork) + 132, 64);
				NewShare->next = NULL;
				
				pthread_mutex_lock(&QueueMutex);
				SubmitShare(&CurrentQueue, NewShare);
				pthread_mutex_unlock(&QueueMutex);		
			}
		} while((MTInfo->AlgoCtx.Nonce < (PrevNonce + 55428800)) && MTInfo->AlgoCtx.Nonce < MaxNonce && !atomic_load(RestartMining + MTInfo->ThreadID));
		
		end = MinerGetCurTime();
		
		double Seconds = SecondsElapsed(begin, end);
		
		pthread_mutex_lock(&StatusMutex);
		GlobalStatus.ThreadHashCounts[MTInfo->ThreadID] = MTInfo->AlgoCtx.Nonce - PrevNonce;
		GlobalStatus.ThreadTimes[MTInfo->ThreadID] = Seconds;
		pthread_mutex_unlock(&StatusMutex);
		
		Log(LOG_INFO, "Thread %d, GPU ID %d, GPU Type: %s: %.02fMH/s\n", MTInfo->ThreadID, *MTInfo->AlgoCtx.GPUIdxs, MTInfo->PlatformContext->Devices[*MTInfo->AlgoCtx.GPUIdxs].DeviceName, ((MTInfo->AlgoCtx.Nonce - PrevNonce)) / (Seconds * 1e6));
	}
	
	// Cleanup function called here
	
	return(NULL);
}
	
void SigHandler(int signal)
{
	pthread_mutex_lock(&Mutex);
	
	ExitFlag = true;
	
	pthread_mutex_unlock(&Mutex);
}

// Signed types indicate there is no default value
// If they are negative, do not set them.

typedef struct _DeviceSettings
{
	uint32_t Index;
	uint32_t Threads;
	uint32_t xIntensity;
	uint32_t Worksize;
	int32_t CoreFreq;
	int32_t MemFreq;
	int32_t FanSpeedPercent;
	int32_t PowerTune;
} DeviceSettings;

// Settings structure for a group of threads mining one algo.
// These threads may be running on diff GPUs, and there may
// be multiple threads per GPU.

typedef struct _AlgoSettings
{
	char *AlgoName;
	uint32_t NumGPUs;
	DeviceSettings *GPUSettings;
	uint32_t TotalThreads;
	uint32_t PoolCount;
	char **PoolURLs;
	WorkerInfo *Workers;
	json_t *AlgoSpecificConfig;
} AlgoSettings;

int ParseConfigurationFile(char *ConfigFileName, AlgoSettings *Settings)
{
	json_t *Config;
	json_error_t Error;
	
	Config = json_load_file(ConfigFileName, JSON_REJECT_DUPLICATES, &Error);
	
	if(!Config)
	{
		Log(LOG_CRITICAL, "Error loading configuration file: %s on line %d.", Error.text, Error.line);
		return(-1);
	}
	
	json_t *AlgoObjArr = json_object_get(Config, "Algorithms");
	if(!AlgoObjArr)
	{
		Log(LOG_CRITICAL, "No 'Algorithms' array found");
		return(-1);
	}
	
	if(!json_array_size(AlgoObjArr))
	{
		Log(LOG_CRITICAL, "Algorithms array empty!");
		return(-1);
	}
	
	json_t *AlgoObj = json_array_get(AlgoObjArr, 0);
	
	json_t *AlgoName = json_object_get(AlgoObj, "name");
	
	if(!AlgoName || !json_is_string(AlgoName))
	{
		Log(LOG_CRITICAL, "Algorithm name missing or not a string.");
		return(-1);
	}
	
	json_t *DevsArr = json_object_get(AlgoObj, "devices");
	
	if(!DevsArr || !json_array_size(DevsArr))
	{
		Log(LOG_CRITICAL, "No devices specified for algorithm %s.", json_string_value(AlgoName));
		return(-1);
	}
	
	Settings->NumGPUs = json_array_size(DevsArr);
	
	Settings->GPUSettings = (DeviceSettings *)malloc(sizeof(DeviceSettings) * Settings->NumGPUs);
	Settings->TotalThreads = 0;
	
	for(int i = 0; i < Settings->NumGPUs; ++i)
	{
		json_t *DeviceObj = json_array_get(DevsArr, i);
		json_t *num = json_object_get(DeviceObj, "index");
		
		if(!num || !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Device structure #%d for algo %s has no index.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		Settings->GPUSettings[i].Index = json_integer_value(num);
		
		num = json_object_get(DeviceObj, "xintensity");
		
		if(!num || !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Device structure #%d for algo %s has no xintensity.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		Settings->GPUSettings[i].xIntensity = json_integer_value(num);
		
		// Optional
		num = json_object_get(DeviceObj, "threads");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to threads in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].Threads = json_integer_value(num);
		else Settings->GPUSettings[i].Threads = 1;
		
		Settings->TotalThreads += Settings->GPUSettings[i].Threads;
		
		// Optional
		num = json_object_get(DeviceObj, "worksize");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to worksize in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].Worksize = json_integer_value(num);
		else Settings->GPUSettings[i].Worksize = 0;
		
		num = json_object_get(DeviceObj, "corefreq");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to corefreq in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].CoreFreq = json_integer_value(num);
		else Settings->GPUSettings[i].CoreFreq = -1;
		
		num = json_object_get(DeviceObj, "memfreq");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to memfreq in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].MemFreq = json_integer_value(num);
		else Settings->GPUSettings[i].MemFreq = -1;
		
		num = json_object_get(DeviceObj, "fanspeed");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to fanspeed in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num && ((json_integer_value(num) > 100) || (json_integer_value(num) < 0)))
		{
			Log(LOG_CRITICAL, "Argument to fanspeed in device structure #%d for algo %s is not a valid percentage (0 - 100).", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
		}
		
		if(num) Settings->GPUSettings[i].FanSpeedPercent = json_integer_value(num);
		else Settings->GPUSettings[i].FanSpeedPercent = -1;
		
		num = json_object_get(DeviceObj, "powertune");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to powertune in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].PowerTune = json_integer_value(num);
		else Settings->GPUSettings[i].PowerTune = 0;
	}
	
	// Remove the devices part from the algo object; it's
	// not part of the algo specific options.
	json_object_del(AlgoObj, "devices");
	
	json_t *PoolsArr = json_object_get(AlgoObj, "pools");
	
	if(!PoolsArr || !json_array_size(PoolsArr))
	{
		Log(LOG_CRITICAL, "No pools specified for algorithm %s.", json_string_value(AlgoName));
		return(-1);
	}
	
	Settings->PoolURLs = (char **)malloc(sizeof(char *) * (json_array_size(PoolsArr) + 1));
	Settings->Workers = (WorkerInfo *)malloc(sizeof(WorkerInfo) * ((json_array_size(PoolsArr) + 1)));
	Settings->PoolCount = json_array_size(PoolsArr);
	
	for(int i = 0; i < Settings->PoolCount; ++i)
	{
		json_t *PoolObj = json_array_get(PoolsArr, i);
		json_t *PoolURL = json_object_get(PoolObj, "url");
		json_t *PoolUser = json_object_get(PoolObj, "user");
		json_t *PoolPass = json_object_get(PoolObj, "pass");
		
		if(!PoolURL || !PoolUser || !PoolPass)
		{
			Log(LOG_CRITICAL, "Pool structure %d for algo %s is missing a URL, username, or password.", i, json_string_value(AlgoName));
			return(-1);
		}
		
		Settings->PoolURLs[i] = (char *)malloc(sizeof(char) * (strlen(json_string_value(PoolURL)) + 1));
		Settings->Workers[i].User = (char *)malloc(sizeof(char) * (strlen(json_string_value(PoolUser)) + 1));
		Settings->Workers[i].Pass = (char *)malloc(sizeof(char) * (strlen(json_string_value(PoolPass)) + 1));
		
		strcpy(Settings->PoolURLs[i], json_string_value(PoolURL));
		strcpy(Settings->Workers[i].User, json_string_value(PoolUser));
		strcpy(Settings->Workers[i].Pass, json_string_value(PoolPass));
		
		Settings->Workers[i].NextWorker = NULL;
	}
	
	// Remove the pools part from the algo object; it's
	// not part of the algo specific options.
	json_object_del(AlgoObj, "pools");
	
	Settings->AlgoSpecificConfig = AlgoObj;
	
	Settings->AlgoName = (char *)malloc(sizeof(char) * (strlen(json_string_value(AlgoName)) + 1));
	strcpy(Settings->AlgoName, json_string_value(AlgoName));
	
	return(0);
}

void FreeSettings(AlgoSettings *Settings)
{
	free(Settings->AlgoName);
	free(Settings->GPUSettings);
	
	for(int i = 0; i < Settings->PoolCount; ++i)
	{
		free(Settings->PoolURLs[i]);
		free(Settings->Workers[i].User);
		free(Settings->Workers[i].Pass);
	}
	
	free(Settings->PoolURLs);
	free(Settings->Workers);
}

// Only doing IPv4 for now.
// TODO: Get Platform index from somewhere else
int main(int argc, char **argv)
{
	PoolInfo Pool;
	AlgoSettings Settings;
	MinerThreadInfo *MThrInfo;
	OCLPlatform PlatformContext;
	int ret, poolsocket, PlatformIdx = 0;
	pthread_t LLPThread, BroadcastThread, *MinerWorker;
	
	InitLogging(LOG_NETDEBUG);
	
	if(argc != 2)
	{
		Log(LOG_CRITICAL, "Usage: %s <config file>", argv[0]);
		return(0);
	}
	
	if(ParseConfigurationFile(argv[1], &Settings) < 0) return(0);
		
	MThrInfo = (MinerThreadInfo *)malloc(sizeof(MinerThreadInfo) * Settings.TotalThreads);
	MinerWorker = (pthread_t *)malloc(sizeof(pthread_t) * Settings.TotalThreads);
	
	#ifdef __linux__
	
	struct sigaction ExitHandler;
	memset(&ExitHandler, 0, sizeof(struct sigaction));
	ExitHandler.sa_handler = SigHandler;
	
	sigaction(SIGINT, &ExitHandler, NULL);
	
	#endif
	
	RestartMining = (atomic_bool *)malloc(sizeof(atomic_bool) * Settings.TotalThreads);
	
	NetworkingInit();
	
	char *TmpPort;
	uint32_t URLOffset;
	
	if(strstr(Settings.PoolURLs[0], "stratum+tcp://"))
		URLOffset = strlen("stratum+tcp://");
	else
		URLOffset = 0;
	
	if(strrchr(Settings.PoolURLs[0] + URLOffset, ':'))
		TmpPort = strrchr(Settings.PoolURLs[0] + URLOffset, ':') + 1;
	else
		TmpPort = "3333";
	
	char *StrippedPoolURL = (char *)malloc(sizeof(char) * (strlen(Settings.PoolURLs[0]) + 1));
	
	int URLSize = URLOffset;
	
	for(; Settings.PoolURLs[0][URLSize] != ':' && Settings.PoolURLs[0][URLSize]; ++URLSize)
		StrippedPoolURL[URLSize - URLOffset] = Settings.PoolURLs[0][URLSize];
	
	StrippedPoolURL[URLSize - URLOffset] = 0x00;
	
	Log(LOG_DEBUG, "Parsed pool URL: %s", StrippedPoolURL);
	
	// TODO: Have ConnectToPool() return a Pool struct
	poolsocket = ConnectToPool(StrippedPoolURL, TmpPort);
	
	if(poolsocket == INVALID_SOCKET)
	{
		Log(LOG_CRITICAL, "Fatal error connecting to pool.");
		return(0);
	}
	
	Log(LOG_NOTIFY, "Successfully connected to pool's LLP.");
	
	// DO NOT FORGET THIS
	CurrentJob.Initialized = false;
	CurrentQueue.first = CurrentQueue.last = NULL;
	
	Pool.sockfd = poolsocket;
	Pool.WorkerData = Settings.Workers[0];
	Pool.MinerThreadCount = Settings.TotalThreads;
	Pool.MinerThreads = (uint32_t *)malloc(sizeof(uint32_t) * Pool.MinerThreadCount);
	
	
	GlobalStatus.ThreadHashCounts = (double *)malloc(sizeof(double) * Settings.TotalThreads);
	GlobalStatus.ThreadTimes = (double *)malloc(sizeof(double) * Settings.TotalThreads);
	
	GlobalStatus.RejectedWork = 0;
	GlobalStatus.SolvedWork = 0;
	
	for(int i = 0; i < Settings.TotalThreads; ++i)
	{
		GlobalStatus.ThreadHashCounts[i] = 0;
		GlobalStatus.ThreadTimes[i] = 0;
	}
	
	for(int i = 0; i < Settings.TotalThreads; ++i) atomic_init(RestartMining + i, false);
	
	ret = pthread_create(&LLPThread, NULL, LLPThreadProc, (void *)&Pool);
	
	if(ret)
	{
		printf("Failed to create LLP thread.\n");
		return(0);
	}
	
	ret = pthread_create(&BroadcastThread, NULL, PoolBroadcastThreadProc, (void *)&Pool);
	
	if(ret)
	{
		printf("Failed to create broadcast thread.\n");
		return(0);
	}
	
	// Note to self - move this list BS into the InitOpenCLPlatformContext() routine
	uint32_t *GPUIdxList = (uint32_t *)malloc(sizeof(uint32_t) * Settings.NumGPUs);
	
	for(int i = 0; i < Settings.NumGPUs; ++i) GPUIdxList[i] = Settings.GPUSettings[i].Index;
	
	ret = InitOpenCLPlatformContext(&PlatformContext, PlatformIdx, Settings.NumGPUs, GPUIdxList);
	if(ret) return(0);
	
	free(GPUIdxList);
	
	for(int i = 0; i < Settings.NumGPUs; ++i)
	{
		PlatformContext.Devices[i].xIntensity = Settings.GPUSettings[i].xIntensity;
		PlatformContext.Devices[i].WorkSize = Settings.GPUSettings[i].Worksize;
	}
	
	// Wait until we've gotten work and filled
	// up the job structure before launching the
	// miner worker threads.
	for(;;)
	{
		pthread_mutex_lock(&JobMutex);
		if(CurrentJob.Initialized) break;
		pthread_mutex_unlock(&JobMutex);
		sleep(1);
	}
	
	pthread_mutex_unlock(&JobMutex);
	
	// Work is ready - time to create the broadcast and miner threads
	//pthread_create(&BroadcastThread, NULL, PoolBroadcastThreadProc, (void *)&Pool);
	
	for(int ThrIdx = 0, GPUIdx = 0; ThrIdx < Settings.TotalThreads && GPUIdx < Settings.NumGPUs; ThrIdx += Settings.GPUSettings[GPUIdx].Threads, ++GPUIdx)
	{
		for(int x = 0; x < Settings.GPUSettings[GPUIdx].Threads; ++x)
		{
			SetupNiroMiner(&MThrInfo[ThrIdx + x].AlgoCtx, &PlatformContext, GPUIdx);
			MThrInfo[ThrIdx + x].ThreadID = ThrIdx + x;
			MThrInfo[ThrIdx + x].TotalMinerThreads = Settings.TotalThreads;
			MThrInfo[ThrIdx + x].PlatformContext = &PlatformContext;
		}		
	}
	
	for(int i = 0; i < Settings.TotalThreads; ++i)
	{
		ret = pthread_create(MinerWorker + i, NULL, MinerThreadProc, MThrInfo + i);
		
		if(ret)
		{
			printf("Failed to create MinerWorker thread.\n");
			return(0);
		}
	}
	
	json_decref(Settings.AlgoSpecificConfig);
	
	while(!ExitFlag) sleep(1);
		
	pthread_cancel(LLPThread);
	
	for(int i = 0; i < Settings.TotalThreads; ++i) pthread_cancel(MinerWorker[i]);
	
	ReleaseOpenCLPlatformContext(&PlatformContext);
		
	FreeSettings(&Settings);
	free(RestartMining);
	free(Pool.MinerThreads);
	
	pthread_cancel(BroadcastThread);
	
	closesocket(poolsocket);
	
	NetworkingShutdown();
	
	// All other threads have been terminated, so no need to
	// acquire the mutex to access the global statistics.
	Log(LOG_NOTIFY, "Mined %d blocks, %d accepted.\nExiting.", GlobalStatus.SolvedWork, GlobalStatus.SolvedWork - GlobalStatus.RejectedWork);
	
	return(0);
}

