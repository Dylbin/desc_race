# desc_race
"desc_race" (CVE-2021-30955) exploit for iOS 15.0 - 15.1.1 (with stable kernel r/w primitives)

# Exploit Method

1. Increase the capacity of IOSurfaceClient
array to 0x2000, goal is to write a pointer whose
content is totally controlled and then use IOSurfaceRootUserClient
interfaces to achieve kernel r/w. The size of the array is 0x2000 * 8 bytes
thus resides in large map of KHEAP_KEXT which is same as KHEAP_DEFAULT.

2. Then allocate a 0x4000 bytes kernel buffer using an assistant kmsg with 0x4000 bytes
ool descriptor which will be overwritten from the back. And then trigger the bug
with the allocated message, called double copyin kmsg,
placed just behind the assistant kernel buffer. And this message
contains a ool ports descriotpor whose count is 0x2000
thus will be rather close to the IOSurfaceClient array.

3. Then you should receive the assistant message. If racing succeeds,
the ool ports descriotpor will be disclosed and
we could locate the IOSurfaceClient array address.

4. Then allocate a 0x4000 bytes kernel buffer again, this will
occupy the aforementioned kernel buffer. This time I construct a fake
kmsg header with proper body. Then I destroy the double
copyin kmsg, kernel will begin with our fake header.
I use a fake mach_msg_ool_descriotpor_t and trigger.

**vm_copy_discard()** with a totally controlled copy.
During the destroying of the copy, the most valuable
lines are in **_vm_map_entry_unlink_ll**:

```
1
2
3
4
5
6
#define _vm_map_entry_unlink_ll(hdr, entry)                             \
	MACRO_BEGIN                                                     \
	(hdr)->nentries--;                                              \
	(entry)->vme_next->vme_prev = (entry)->vme_prev;                \
	(entry)->vme_prev->vme_next = (entry)->vme_next;                \
	MACRO_END
```

The **entry** is under our control, this give us a perfect
r/w primitive. I use this to write a controlled pointer
to the IOSurfaceClient array, and then achieve kernel
r/w combined with IOSurfaceRootUserClient interfaces.

I have read bazad’s post One byte to rule them all time and
time again during developing this exploit, and used the same
technique, faking vm_copy_t, in his exploit. But there are
some points differ.

1. XNU signs the message and we can no longer receive a
corrupted kmsg.

2. In the destroying procedure, I set vm_object’s mapping_in_progress
to let the kernel spin thus won’t panic due to zone
check.

Much thanks to bazad for his great post, and WangTielei for
letting me know that IOSurfaceClient interfaces are now invalid
for r/w primitive, and pedantcoder for his kindness.
