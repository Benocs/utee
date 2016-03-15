#ifndef __SMP_H_
#define __SMP_H_

#define barrier() __asm__ __volatile__("": : :"memory")

#define smp_mb__before_atomic() barrier()
#define smp_mb__after_atomic()  barrier()

#define LOCK_PREFIX "\n\tlock; "

typedef struct {
    uint64_t counter;
} atomic_t;

/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
static inline void atomic_inc(atomic_t *v)
{
    asm volatile(LOCK_PREFIX "incl %0"
             : "+m" (v->counter));
}

/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
static inline void atomic_dec(atomic_t *v)
{
    asm volatile(LOCK_PREFIX "decl %0"
             : "+m" (v->counter));
}

#endif /* __SMP_H_ */
