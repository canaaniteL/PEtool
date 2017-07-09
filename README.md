# PEtool
## 1.简介
	该项目使用win32 API在VC6++上完成开发。
	核心部件代码在PEtool.cpp和PE_Parse.cpp中。
	主要功能是完成对PE文件（.exe .dll .com .sys）分析，解析出PE各部分结构。
### 2.核心功能
* a.解析PE文件
	包括解析PE节表、目录表、资源表、导入表、导出表等结构。
* b.软件加壳
	选择需要加壳的软件A后，程序会读取壳子程序B，并在B中增加一个节（大小为A的文件size）存放A。
	最终生成的程序放在"c：\testShell"，文件名与A相同。
	使用的加壳方式只能防静态分析，对于动态分析没有杀伤力。
	*** 解壳主要原理 ***：
	* 1.判断是否新加了节。如果是，跳转到第二步。否则退出。
	* 2.将新加入的节读取到堆中。
	* 3.以挂起形式运行B，并获取子进程B的context。
	* 4.卸载B的内存。
	* 5.在B进程分配内存空间，位置为A程序的ImageBase处，大小为A的SizeofImage。
	* 6.重新修改context，context的ebx为新分配的内存空间首地址【也就是A的imagebase】,eax为A程序的AddressOfEntryPoint。
	* 7.context重设一下，再把B程序ResumeThread,拉起来。
	
	
* c.DLL注入