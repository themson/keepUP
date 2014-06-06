keepUP
======

KeepNote Local IPC exploit


This POC is written in Python, as such under 2.7.* the GIL will drastically impact the speed of the attack.
A speed increase can be had by leveraging taskset to force process affinity to one core. However, if speed is a major concern, C is the answer.
