keepUP
======

KeepNote Local IPC exploit

I've also written a threaded version of this POC, however, under Python 2.7.* the GIL drastically impacts the speed of the attack. A speed increase can be had by leveraging taskset to force process affinity to one core, however, if speed is a major concern, C is the answer.
