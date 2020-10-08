# coding:utf-8
#! /usr/bin/env python

import keyboard

def abc(x):
    a = keyboard.KeyboardEvent('down', 28, 'enter')
    #按键事件a为按下enter键，第二个参数如果不知道每个按键的值就随便写，
    #如果想知道按键的值可以用hook绑定所有事件后，输出x.scan_code即可
    if x.event_type == 'down' and x.name == a.name:
        print("你按下了enter键")
    #当监听的事件为enter键，且是按下的时候

keyboard.hook(abc)
# keyboard.hook_key('enter', bcd)
# recorded = keyboard.record(until='esc')
keyboard.wait()

print 1