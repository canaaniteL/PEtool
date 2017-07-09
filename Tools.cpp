// Tools.cpp: implementation of the Tools class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Tools.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

void __cdecl OutputDebugStringF(const char *format, ...)  
{  
    va_list vlArgs;  
    char    *strBuffer = (char*)GlobalAlloc(GPTR, 4096);  
	
    va_start(vlArgs, format);  
    _vsnprintf(strBuffer, 4096 - 1, format, vlArgs);  
    va_end(vlArgs);  
    strcat(strBuffer, "\n");  
    OutputDebugStringA(strBuffer);  
    GlobalFree(strBuffer);  
    return;  
}  
DWORD CopyFromImageBufferToFileBuffer(IN PVOID pImageBuffer,OUT LPVOID* pNewFileBuffer ,DWORD len){

	PIMAGE_DOS_HEADER pDosHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_FILE_HEADER pPEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader=NULL;
	PIMAGE_SECTION_HEADER pSectionHeader=NULL;

//	DWORD ImageSize=0;

	//判断文件缓冲区是否有效
	if(pImageBuffer==NULL){
		OutputDebugStringF("内存镜像缓冲区指针无效\n");
		return 0;
	}

	//判断该文件是否是PE文件
	if(*((PWORD)pImageBuffer)!=IMAGE_DOS_SIGNATURE){
		OutputDebugStringF("不是有效的DOS内存镜像缓冲区\n");
		return 0;
	}
	pDosHeader=(PIMAGE_DOS_HEADER)(pImageBuffer);


	if(*((PDWORD)((DWORD)pImageBuffer+pDosHeader->e_lfanew))!=IMAGE_NT_SIGNATURE){  //这里注意：FileBuffer是一个指针，也就是一个地址，所以转型为DWROD与pDosHeader->e_lfanew相加
		OutputDebugStringF("该文件不是有效的PE文件");
		return 0;
	}

//	printf("DOS的开始地址是：%x\n",pDosHeader);
	//NT头指针
	pNTHeaders=(PIMAGE_NT_HEADERS)((DWORD)pDosHeader+pDosHeader->e_lfanew);
//	printf("NT的开始地址是：%x\n",pNTHeaders);
    //PE头指针等于NT头指针加四
	pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)pDosHeader+pDosHeader->e_lfanew)+4);                          //	pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4);
//	printf("PE的开始地址是：%x\n",pPEHeader);
	
	//血的教训，一个指针加上一个整数，加上的实际的大小是该指针表示的数据类型【去掉一个*】乘以整数
	pOptionalHeader=(PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);//指针在加数时务必将其转化为整形
//	printf("optional的开始地址是：%x\n",pOptionalHeader);

	pSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader+pPEHeader->SizeOfOptionalHeader);
//	printf("section表的开始地址是：%x\n",pSectionHeader);

	
	//根据SIZE_OF_IMAGE来分配内存缓冲区的大小，虽然每一个应用程序在理论上都拥有独立的4GB虚拟内存，但是还是根据SIZE FOF IMAGE来分配内存大小
	PVOID pTempFileBuffer=NULL;
	pTempFileBuffer=malloc(len);
	printf("文件的大小为%x\n\r",len);
	if(pTempFileBuffer==NULL){
		OutputDebugStringF("新的文件缓冲区申请失败\r\n");
		free(pTempFileBuffer);
		return 0;
		
	}

	memset(pTempFileBuffer,0,len);

	//开始从文件缓冲区拷贝到镜像缓冲区中  1：第一步：将所有的头拷贝到镜像缓冲区中 DosHeader+NTHeader+SectionHeader
	memcpy(pTempFileBuffer,pImageBuffer,pOptionalHeader->SizeOfHeaders);


	int i;
	PIMAGE_SECTION_HEADER pTempSectionHeader=pSectionHeader;
	for(i=0;i<pPEHeader->NumberOfSections;i++,pTempSectionHeader++){
		OutputDebugStringF("1\n");
		memcpy((void*)((DWORD)pTempFileBuffer+pTempSectionHeader->PointerToRawData),(void*)((DWORD)pDosHeader+pTempSectionHeader->VirtualAddress),pTempSectionHeader->SizeOfRawData);
		OutputDebugStringF("2\n");
	}
		OutputDebugStringF("helloc\n");

	*pNewFileBuffer=pTempFileBuffer;
	pTempFileBuffer=NULL;
	

	return len;

	}

DWORD CopyFromFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer){



	PIMAGE_DOS_HEADER pDosHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_FILE_HEADER pPEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader=NULL;
	PIMAGE_SECTION_HEADER pSectionHeader=NULL;

	DWORD ImageSize=0;

	//判断文件缓冲区是否有效
	if(pFileBuffer==NULL){
		OutputDebugStringF("文件缓冲区指针无效\n");
		return 0;
	}

	//判断该文件是否是PE文件
	if(*((PWORD)pFileBuffer)!=IMAGE_DOS_SIGNATURE){
		OutputDebugStringF("不是有效的DOS文件\n");
		return 0;
	}
	pDosHeader=(PIMAGE_DOS_HEADER)(pFileBuffer);
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew))!=IMAGE_NT_SIGNATURE){  //这里注意：FileBuffer是一个指针，也就是一个地址，所以转型为DWROD与pDosHeader->e_lfanew相加
		OutputDebugStringF("该文件不是有效的PE文件");
		return 0;
	}

//	printf("DOS的开始地址是：%x\n",pDosHeader);
	//NT头指针
	pNTHeaders=(PIMAGE_NT_HEADERS)((DWORD)pDosHeader+pDosHeader->e_lfanew);
//	printf("NT的开始地址是：%x\n",pNTHeaders);
    //PE头指针等于NT头指针加四
	pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4);
//	printf("PE的开始地址是：%x\n",pPEHeader);
	
	//血的教训，一个指针加上一个整数，加上的实际的大小是该指针表示的数据类型【去掉一个*】乘以整数
	pOptionalHeader=(PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);//指针在加数时务必将其转化为整形
//	printf("optional的开始地址是：%x\n",pOptionalHeader);

	pSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader+pPEHeader->SizeOfOptionalHeader);
//	printf("section表的开始地址是：%x\n",pSectionHeader);

	
	//根据SIZE_OF_IMAGE来分配内存缓冲区的大小，虽然每一个应用程序在理论上都拥有独立的4GB虚拟内存，但是还是根据SIZE FOF IMAGE来分配内存大小
	LPVOID pTempImageBuffer=NULL;
	pTempImageBuffer=malloc(pOptionalHeader->SizeOfImage);
	printf("文件的sizeofImage为%x\n",pOptionalHeader->SizeOfImage);
	if(pTempImageBuffer==NULL){
		OutputDebugStringF("分配内存镜像文件失败\n");
	}

	memset(pTempImageBuffer,0,pOptionalHeader->SizeOfImage);

	//开始从文件缓冲区拷贝到镜像缓冲区中  1：第一步：将所有的头拷贝到镜像缓冲区中 DosHeader+NTHeader+SectionHeader
	memcpy(pTempImageBuffer,pFileBuffer,pOptionalHeader->SizeOfHeaders);
	

	int i;
	PIMAGE_SECTION_HEADER pTempSectionHeader=pSectionHeader;

	for(i=0;i<pPEHeader->NumberOfSections;i++,pTempSectionHeader++){
		memcpy((PVOID)((DWORD)pTempImageBuffer+pTempSectionHeader->VirtualAddress),(void*)((DWORD)pDosHeader+pTempSectionHeader->PointerToRawData),pTempSectionHeader->SizeOfRawData);
	}

	*pImageBuffer=pTempImageBuffer;
	pTempImageBuffer=NULL;
	

	return pOptionalHeader->SizeOfImage;

}
//将文件读取到文件缓冲区中
DWORD ReadFileToBuffer(IN LPSTR FilePath,OUT LPVOID* pFileBuffer){

	FILE* pFile=NULL;
	DWORD fileSize=0;
	LPVOID pTempFileBuffer=NULL; 


	pFile=fopen(FilePath,"rb");

	if(!pFile){
		OutputDebugStringF("无法打开该文件\n");
		return 0;
	}
	
	fseek(pFile,0,SEEK_END);

	fileSize=ftell(pFile);
	
	fseek(pFile,0,SEEK_SET);

	//分配内存空间
	pTempFileBuffer=malloc(fileSize);
	
	//强申请的空间初始化为0
	memset(pTempFileBuffer,0,fileSize);
	if(!pTempFileBuffer){
		OutputDebugStringF("申请空间失败\n");
		fclose(pFile);
		return 0;
	}
	
	int n=fread(pTempFileBuffer,fileSize,1,pFile);

	if(!n){
		OutputDebugStringF("读取文件失败\n");
		fclose(pFile);
		free(pTempFileBuffer);
		return 0;
	}

	*pFileBuffer=pTempFileBuffer;
	pTempFileBuffer=NULL;

	return fileSize;
}
BOOL MemeryToFile(LPVOID pMemBuffer,size_t size,LPSTR lpszFile){
	FILE* fp=NULL;
	fp=fopen(lpszFile,"wb+");
	if(fp==NULL){
		return FALSE;
	}
	fwrite(pMemBuffer,size,1,fp);
	fclose(fp);
	fp=NULL;
	return TRUE;
}

DWORD NumAlign(DWORD num,DWORD align){
	WORD i=num/align;
	WORD j=num%align;
	if(!j) {
		return num;
	}
	return align*(i+1);
}
//将PE文件头里面的节表往前挪动
void MoveHead(IN LPVOID pFileBuffer,OUT LPVOID* pNewBuffer,DWORD len){
	LPVOID pnewbuf=NULL;
	PIMAGE_DOS_HEADER pDosHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_FILE_HEADER pPEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader=NULL;
	PIMAGE_SECTION_HEADER pSectionHeader=NULL;
	PIMAGE_EXPORT_DIRECTORY pExport=NULL;
	BOOL isOK=FALSE;
	if(!pFileBuffer){
	
		OutputDebugStringF("文件->缓冲区失败\n");
		return;
	}
	pDosHeader=(PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4);
	pOptionHeader=(PIMAGE_OPTIONAL_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader=(PIMAGE_SECTION_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER+pPEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER TP_head_end=pSectionHeader+pPEHeader->NumberOfSections;
	DWORD lenOfHead=pDosHeader->e_lfanew+4+IMAGE_SIZEOF_FILE_HEADER+pPEHeader->SizeOfOptionalHeader+pPEHeader->NumberOfSections*40;
	pnewbuf=malloc(len);
	memset(pnewbuf,0,len);
	memcpy(pnewbuf,pFileBuffer,len);
	memcpy((PVOID)((DWORD)pnewbuf+64),(PVOID)((DWORD)pnewbuf+pDosHeader->e_lfanew),lenOfHead-pDosHeader->e_lfanew);
	*(PDWORD)((DWORD)pnewbuf+60)=64;//修改e_lfanew
	DWORD addrHead_tail=64+4+IMAGE_SIZEOF_FILE_HEADER+pPEHeader->SizeOfOptionalHeader+pPEHeader->NumberOfSections*40+(DWORD)pnewbuf;
	memset((PVOID)addrHead_tail,0,pDosHeader->e_lfanew-64);
	
	*pNewBuffer=pnewbuf;
	pnewbuf=NULL;
//	isOK=MemeryToFile(pnewbuf,len,FILEPATH_OUT);
//	if(isOK){
//		printf("存盘成功");
//	}

}

BOOL AddSecion(IN LPVOID pFileBuffer,OUT LPVOID* pNewBuffer,IN LPVOID pPEBuffer,DWORD AddSecLen,DWORD len){
	LPVOID pnewbuf=NULL;
	PIMAGE_DOS_HEADER pDosHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_FILE_HEADER pPEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader=NULL;
	PIMAGE_SECTION_HEADER pSectionHeader=NULL;
	PIMAGE_EXPORT_DIRECTORY pExport=NULL;

	if(!pFileBuffer){
	
		OutputDebugStringF("文件->缓冲区失败\n");
		return FALSE;
	}
	pDosHeader=(PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4);
	pOptionHeader=(PIMAGE_OPTIONAL_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader=(PIMAGE_SECTION_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER+pPEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER TP_head_end=pSectionHeader+pPEHeader->NumberOfSections;
	//判断是否有足够的空间放一个节表
	DWORD lenOfHead=pDosHeader->e_lfanew+4+IMAGE_SIZEOF_FILE_HEADER+pPEHeader->SizeOfOptionalHeader+pPEHeader->NumberOfSections*40;
	printf("头里面所有实际内容大小：%d\n",lenOfHead);
	if(pOptionHeader->SizeOfHeaders-lenOfHead<80){
		OutputDebugStringF("空闲区不够80个字节\n");
		LPVOID pNewFileBuffer=NULL;
		MoveHead(pFileBuffer,&pNewFileBuffer,len);
		free(pFileBuffer);
		pFileBuffer=pNewFileBuffer;
		
	}
	//判断这个壳程序有没有额外数据（最后一个节末尾）
	DWORD dwRestData=len-(pSectionHeader[pPEHeader->NumberOfSections-1].PointerToRawData+pSectionHeader[pPEHeader->NumberOfSections-1].SizeOfRawData);
	if(dwRestData>0)
	{
		OutputDebugStringF("有剩余数据\n");
	}
	//拷贝第一个节到最后
	memcpy(TP_head_end,pSectionHeader,40);
	//最后一个节留一个节长的0
	TP_head_end++;
	memset(TP_head_end,0,40);
	//节的数量加1
	pPEHeader->NumberOfSections++;
	//修改sizeofimage
	pOptionHeader->SizeOfImage+=AddSecLen;
	

	//修改新增节表的属性信息
	TP_head_end--;
	pSectionHeader=pSectionHeader+pPEHeader->NumberOfSections-2;
	TP_head_end->VirtualAddress=NumAlign(pSectionHeader->Misc.VirtualSize,pOptionHeader->SectionAlignment)+pSectionHeader->VirtualAddress;
	TP_head_end->PointerToRawData=NumAlign(pSectionHeader->SizeOfRawData,pOptionHeader->FileAlignment)+pSectionHeader->PointerToRawData+dwRestData;
	TP_head_end->SizeOfRawData=AddSecLen;
	TP_head_end->Misc.VirtualSize=AddSecLen;
	memcpy(TP_head_end->Name,".canaan",strlen(".canaan"));
	OutputDebugStringF("新增节信息：\n name:%s\n",TP_head_end->Name);
	
	OutputDebugStringF("virtualSize:%x\n",TP_head_end->Misc.VirtualSize);
	OutputDebugStringF("va:%x\n",TP_head_end->VirtualAddress);
	OutputDebugStringF("sizeofRawData:%x\n",TP_head_end->SizeOfRawData);
	OutputDebugStringF("pointerToRawData:%x\n",TP_head_end->PointerToRawData);
	BOOL addBehind=TRUE;//有些pe文件在末尾加了东西。。。?  没有加。。。是我自己搞错了。。，自己在添加节的时候搞错了。
	if(addBehind){
		pnewbuf=malloc(len+AddSecLen);
		memset(pnewbuf,0,len+AddSecLen);
		memcpy(pnewbuf,pFileBuffer,len);
		memcpy((LPVOID)((DWORD)pnewbuf+len),pPEBuffer,AddSecLen);
	}else{
		/*
			这个地方我也是忘了出于什么考虑加个else....
		*/
		pnewbuf=malloc(len);
		memset((PVOID)(TP_head_end->PointerToRawData+(DWORD)pFileBuffer),0,TP_head_end->SizeOfRawData);
		memcpy(pnewbuf,pFileBuffer,len);
	}
	*pNewBuffer=pnewbuf;
	pnewbuf=NULL;
	return TRUE;
}