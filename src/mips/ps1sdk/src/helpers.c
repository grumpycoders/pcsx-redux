#include <ps1sdk.h>
#include <helpers.h>

/* accessors for getting and setting COP0 registers */
uint32_t C0_get_BPC(void) { register uint32_t rv; __asm__ __volatile__("mfc0 %0, $3" : "=&r" (rv)); return rv; }
uint32_t C0_get_BDA(void) { register uint32_t rv; __asm__ __volatile__("mfc0 %0, $5" : "=&r" (rv)); return rv; }
uint32_t C0_get_DCIC(void) { register uint32_t rv; __asm__ __volatile__("mfc0 %0, $7" : "=&r" (rv)); return rv; }
uint32_t C0_get_BADVADDR(void) { register uint32_t rv; __asm__ __volatile__("mfc0 %0, $8" : "=&r" (rv)); return rv; }
uint32_t C0_get_BDAM(void) { register uint32_t rv; __asm__ __volatile__("mfc0 %0, $9" : "=&r" (rv)); return rv; }
uint32_t C0_get_BPCM(void) { register uint32_t rv; __asm__ __volatile__("mfc0 %0, $11" : "=&r" (rv)); return rv; }
uint32_t C0_get_STATUS(void) { register uint32_t rv; __asm__ __volatile__("mfc0 %0, $12" : "=&r" (rv)); return rv; }
uint32_t C0_get_CAUSE(void) { register uint32_t rv; __asm__ __volatile__("mfc0 %0, $13" : "=&r" (rv)); return rv; }
uint32_t C0_get_EPC(void) { register uint32_t rv; __asm__ __volatile__("mfc0 %0, $14" : "=&r" (rv)); return rv; }
uint32_t C0_get_PRID(void) { register uint32_t rv; __asm__ __volatile__("mfc0 %0, $15" : "=&r" (rv)); return rv; }

void C0_set_BPC(uint32_t v)  { __asm__ __volatile__("mtc0 %0, $3" : : "r" (v)); }
void C0_set_BDA(uint32_t v)  { __asm__ __volatile__("mtc0 %0, $5" : : "r" (v)); }
void C0_set_DCIC(uint32_t v)  { __asm__ __volatile__("mtc0 %0, $7" : : "r" (v)); }
void C0_set_BADVADDR(uint32_t v)  { __asm__ __volatile__("mtc0 %0, $8" : : "r" (v)); }
void C0_set_BDAM(uint32_t v)  { __asm__ __volatile__("mtc0 %0, $9" : : "r" (v)); }
void C0_set_BPCM(uint32_t v)  { __asm__ __volatile__("mtc0 %0, $11" : : "r" (v)); }
void C0_set_STATUS(uint32_t v)  { __asm__ __volatile__("mtc0 %0, $12" : : "r" (v)); }
void C0_set_CAUSE(uint32_t v)  { __asm__ __volatile__("mtc0 %0, $13" : : "r" (v)); }
void C0_set_EPC(uint32_t v)  { __asm__ __volatile__("mtc0 %0, $14" : : "r" (v)); }
void C0_set_PRID(uint32_t v)  { __asm__ __volatile__("mtc0 %0, $15" : : "r" (v)); }
