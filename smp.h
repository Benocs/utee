#ifndef __SMP_H_
#define __SMP_H_

/*
 * This file contains code from the Linux kernel from the following files:
 * arch/x86/include/asm/atomic.h
 * asm/atomic64_64.h
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#define barrier() __asm__ __volatile__("": : :"memory")

#define smp_mb__before_atomic() barrier()
#define smp_mb__after_atomic()  barrier()

#define LOCK_PREFIX "\n\tlock; "

typedef struct {
    volatile uint64_t counter;
} atomic_t;

/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 */

#define ATOMIC_INIT(i)  { (i) }

/**
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically reads the value of @v.
 */
static inline uint64_t atomic_read(const atomic_t *v)
{
    return (*(volatile uint64_t *)&(v)->counter);
}

/**
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
static inline void atomic_set(atomic_t *v, uint64_t i)
{
    v->counter = i;
}

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */
static inline void atomic_add(uint64_t i, atomic_t *v)
{
    asm volatile(LOCK_PREFIX "addq %1,%0"
             : "=m" (v->counter)
             : "er" (i), "m" (v->counter));
}

/**
 * atomic_sub - subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.
 */
static inline void atomic_sub(uint64_t i, atomic_t *v)
{
    asm volatile(LOCK_PREFIX "subq %1,%0"
             : "=m" (v->counter)
             : "er" (i), "m" (v->counter));
}

/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
static inline void atomic_inc(atomic_t *v)
{
    asm volatile(LOCK_PREFIX "incq %0"
             : "=m" (v->counter)
             : "m" (v->counter));
}

/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
static inline void atomic_dec(atomic_t *v)
{
    asm volatile(LOCK_PREFIX "decq %0"
             : "=m" (v->counter)
             : "m" (v->counter));
}

#endif /* __SMP_H_ */
