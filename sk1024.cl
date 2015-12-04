#ifndef SK1024_CL
#define SK1024_CL

__constant static const ulong keccakf_1600_rc[24] = 
{
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL
};

inline void keccak_block(ulong *s, const uint isolate)
{
	ulong m[5], v, w;
	
	#pragma unroll 1
	for(int i = 0; i < (24 & isolate); ++i)
	{	
		m[0] = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20] ^ rotate(s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22], 1UL);
		m[1] = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21] ^ rotate(s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23], 1UL);
		m[2] = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22] ^ rotate(s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24], 1UL);
		m[3] = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23] ^ rotate(s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20], 1UL);
		m[4] = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24] ^ rotate(s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21], 1UL);
		
		v = s[1] ^ m[0];
		s[0] ^= m[4];
		s[1] = rotate(s[6] ^ m[0], 44UL);
		s[6] = rotate(s[9] ^ m[3], 20UL);
		s[9] = rotate(s[22] ^ m[1], 61UL);
		s[22] = rotate(s[14] ^ m[3], 39UL);
		s[14] = rotate(s[20] ^ m[4], 18UL);
		s[20] = rotate(s[2] ^ m[1], 62UL);
		s[2] = rotate(s[12] ^ m[1], 43UL);
		s[12] = rotate(s[13] ^ m[2], 25UL);
		s[13] = rotate(s[19] ^ m[3], 8UL);
		s[19] = rotate(s[23] ^ m[2], 56UL);
		s[23] = rotate(s[15] ^ m[4], 41UL);
		s[15] = rotate(s[4] ^ m[3], 27UL);
		s[4] = rotate(s[24] ^ m[3], 14UL);
		s[24] = rotate(s[21] ^ m[0], 2UL);
		s[21] = rotate(s[8] ^ m[2], 55UL);
		s[8] = rotate(s[16] ^ m[0], 45UL);
		s[16] = rotate(s[5] ^ m[4], 36UL);
		s[5] = rotate(s[3] ^ m[2], 28UL);
		s[3] = rotate(s[18] ^ m[2], 21UL);
		s[18] = rotate(s[17] ^ m[1], 15UL);
		s[17] = rotate(s[11] ^ m[0], 10UL);
		s[11] = rotate(s[7] ^ m[1], 6UL);
		s[7] = rotate(s[10] ^ m[4], 3UL);
		s[10] = rotate(v, 1UL);
		
		v = s[0]; w = s[1]; s[0] = bitselect(s[0] ^ s[2], s[0], s[1]); s[1] = bitselect(s[1] ^ s[3], s[1], s[2]); s[2] = bitselect(s[2] ^ s[4], s[2], s[3]); s[3] = bitselect(s[3] ^ v, s[3], s[4]); s[4] = bitselect(s[4] ^ w, s[4], v);
		v = s[5]; w = s[6]; s[5] = bitselect(s[5] ^ s[7], s[5], s[6]); s[6] = bitselect(s[6] ^ s[8], s[6], s[7]); s[7] = bitselect(s[7] ^ s[9], s[7], s[8]); s[8] = bitselect(s[8] ^ v, s[8], s[9]); s[9] = bitselect(s[9] ^ w, s[9], v);
		v = s[10]; w = s[11]; s[10] = bitselect(s[10] ^ s[12], s[10], s[11]); s[11] = bitselect(s[11] ^ s[13], s[11], s[12]); s[12] = bitselect(s[12] ^ s[14], s[12], s[13]); s[13] = bitselect(s[13] ^ v, s[13], s[14]); s[14] = bitselect(s[14] ^ w, s[14], v);
		v = s[15]; w = s[16]; s[15] = bitselect(s[15] ^ s[17], s[15], s[16]); s[16] = bitselect(s[16] ^ s[18], s[16], s[17]); s[17] = bitselect(s[17] ^ s[19], s[17], s[18]); s[18] = bitselect(s[18] ^ v, s[18], s[19]); s[19] = bitselect(s[19] ^ w, s[19], v);
		v = s[20]; w = s[21]; s[20] = bitselect(s[20] ^ s[22], s[20], s[21]); s[21] = bitselect(s[21] ^ s[23], s[21], s[22]); s[22] = bitselect(s[22] ^ s[24], s[22], s[23]); s[23] = bitselect(s[23] ^ v, s[23], s[24]); s[24] = bitselect(s[24] ^ w, s[24], v);
		
		s[0] ^= keccakf_1600_rc[i];
	}
};

ulong SKEIN_ROT(const uint2 x, const uint y)
{
	if(y < 32) return(as_ulong(amd_bitalign(x, x.s10, 32 - y)));
	else if(y > 32) return(as_ulong(amd_bitalign(x.s10, x, 32 - (y - 32))));
	
	return(as_ulong(x.s10));
}

void SkeinMix8(ulong8 *pv0, ulong8 *pv1, const uint rc0, const uint rc1, const uint rc2, const uint rc3, const uint rc4, const uint rc5, const uint rc6, const uint rc7)
{
	*pv0 += *pv1;
	(*pv1).s0 = SKEIN_ROT(as_uint2((*pv1).s0), rc0);
	(*pv1).s1 = SKEIN_ROT(as_uint2((*pv1).s1), rc1);
	(*pv1).s2 = SKEIN_ROT(as_uint2((*pv1).s2), rc2);
	(*pv1).s3 = SKEIN_ROT(as_uint2((*pv1).s3), rc3);
	(*pv1).s4 = SKEIN_ROT(as_uint2((*pv1).s4), rc4);
	(*pv1).s5 = SKEIN_ROT(as_uint2((*pv1).s5), rc5);
	(*pv1).s6 = SKEIN_ROT(as_uint2((*pv1).s6), rc6);
	(*pv1).s7 = SKEIN_ROT(as_uint2((*pv1).s7), rc7);
	*pv1 ^= *pv0;
}

#define SKEIN_INJECT_KEY(p, s)	do { \
	p += h; \
	p.sd += t[s % 3]; \
	p.se += t[(s + 1) % 3]; \
	p.sf += s; \
} while(0)

ulong16 SkeinEvenRound(ulong16 p, const ulong16 h, const ulong *t, const uint s)
{
	SKEIN_INJECT_KEY(p, s);
	ulong8 pv0 = p.even, pv1 = p.odd;
	
	SkeinMix8(&pv0, &pv1, 55, 43, 37, 40, 16, 22, 38, 12);
	pv0 = shuffle(pv0, (ulong8)(0, 1, 3, 2, 5, 6, 7, 4));
	pv1 = shuffle(pv1, (ulong8)(4, 6, 5, 7, 3, 1, 2, 0));
	
	SkeinMix8(&pv0, &pv1, 25, 25, 46, 13, 14, 13, 52, 57);
	pv0 = shuffle(pv0, (ulong8)(0, 1, 3, 2, 5, 6, 7, 4));
	pv1 = shuffle(pv1, (ulong8)(4, 6, 5, 7, 3, 1, 2, 0));
	
	SkeinMix8(&pv0, &pv1, 33, 8, 18, 57, 21, 12, 32, 54);
	pv0 = shuffle(pv0, (ulong8)(0, 1, 3, 2, 5, 6, 7, 4));
	pv1 = shuffle(pv1, (ulong8)(4, 6, 5, 7, 3, 1, 2, 0));
	
	SkeinMix8(&pv0, &pv1, 34, 43, 25, 60, 44, 9, 59, 34);
	pv0 = shuffle(pv0, (ulong8)(0, 1, 3, 2, 5, 6, 7, 4));
	pv1 = shuffle(pv1, (ulong8)(4, 6, 5, 7, 3, 1, 2, 0));
	
	return(shuffle2(pv0, pv1, (ulong16)(0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15)));
}

ulong16 SkeinOddRound(ulong16 p, const ulong16 h, const ulong *t, const uint s)
{
	SKEIN_INJECT_KEY(p, s);
	ulong8 pv0 = p.even, pv1 = p.odd;
	
	SkeinMix8(&pv0, &pv1, 28, 7, 47, 48, 51, 9, 35, 41);
	pv0 = shuffle(pv0, (ulong8)(0, 1, 3, 2, 5, 6, 7, 4));
	pv1 = shuffle(pv1, (ulong8)(4, 6, 5, 7, 3, 1, 2, 0));
	
	SkeinMix8(&pv0, &pv1, 17, 6, 18, 25, 43, 42, 40, 15);
	pv0 = shuffle(pv0, (ulong8)(0, 1, 3, 2, 5, 6, 7, 4));
	pv1 = shuffle(pv1, (ulong8)(4, 6, 5, 7, 3, 1, 2, 0));
	
	SkeinMix8(&pv0, &pv1, 58, 7, 32, 45, 19, 18, 2, 56);
	pv0 = shuffle(pv0, (ulong8)(0, 1, 3, 2, 5, 6, 7, 4));
	pv1 = shuffle(pv1, (ulong8)(4, 6, 5, 7, 3, 1, 2, 0));
	
	SkeinMix8(&pv0, &pv1, 47, 49, 27, 58, 37, 48, 53, 56);
	pv0 = shuffle(pv0, (ulong8)(0, 1, 3, 2, 5, 6, 7, 4));
	pv1 = shuffle(pv1, (ulong8)(4, 6, 5, 7, 3, 1, 2, 0));
	
	return(shuffle2(pv0, pv1, (ulong16)(0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15)));
}

ulong16 Skein1024Block(ulong16 p, ulong16 h, ulong h17, const ulong *t)
{
	#pragma unroll
	for(int i = 0; i < 20; ++i)
	{
		p = SkeinEvenRound(p, h, t, i);
		++i;
		ulong tmp = h.s0;
		h = shuffle(h, (ulong16)(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0));
		h.sf = h17;
		h17 = tmp;
		
		p = SkeinOddRound(p, h, t, i);
		tmp = h.s0;
		h = shuffle(h, (ulong16)(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0));
		h.sf = h17;
		h17 = tmp;
	}
	
	SKEIN_INJECT_KEY(p, 20);
	return(p);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void sk1024(const __global ulong *uMessage, __constant ulong *c_hv, __constant ulong *highNonce, __global ulong *output, const uint isolate, const ulong target)
{	
	const ulong nonce = ((ulong)get_global_id(0)) + *highNonce, t1[3] = { 0xD8UL, 0xB000000000000000UL, 0xB0000000000000D8UL }, t2[3] = { 0x08UL, 0xFF00000000000000UL, 0xFF00000000000008UL };
	ulong16 p, m = 0, h = 0;
	ulong h17, state[25];
	
	m.lo = vload8(2, uMessage);
	m.s8 = uMessage[24];
	m.s9 = uMessage[25];
	m.sa = nonce;
	
	p = m;
	
	h = vload16(0, c_hv);
	h17 = c_hv[16];
	
	#pragma unroll 1
	for(int i = 0; i < 2; ++i)
	{
		p = Skein1024Block(p, h, h17, ((i) ? t2 : t1));
		
		h = m ^ p;
		h17 = 0x5555555555555555UL ^ h.s0 ^ h.s1 ^ h.s2 ^ h.s3 ^ h.s4 ^ h.s5 ^ h.s6 ^ h.s7 ^ h.s8 ^ h.s9 ^ h.sa ^ h.sb ^ h.sc ^ h.sd ^ h.se ^ h.sf;
		if(!i) p = 0;
	}
	
	vstore8(p.lo, 0, state);
	state[8] = p.s8;
	
	#pragma unroll
	for(int i = 9; i < 25; ++i) state[i] = 0;
	
	#pragma unroll 1
	for(int i = 0; i < 3; ++i)
	{
		keccak_block(state, isolate);
		if(!i)
		{
			state[0] ^= p.s9;
			state[1] ^= p.sa;
			state[2] ^= p.sb;
			state[3] ^= p.sc;
			state[4] ^= p.sd;
			state[5] ^= p.se;
			state[6] ^= p.sf;
			state[7] ^= 0x05UL;
			state[8] ^= 1UL << 63UL;
		}
	}
	
	if(state[6] <= target) output[output[0xFF]++] = nonce;
}

#endif
