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

	//�ж��ļ��������Ƿ���Ч
	if(pImageBuffer==NULL){
		OutputDebugStringF("�ڴ澵�񻺳���ָ����Ч\n");
		return 0;
	}

	//�жϸ��ļ��Ƿ���PE�ļ�
	if(*((PWORD)pImageBuffer)!=IMAGE_DOS_SIGNATURE){
		OutputDebugStringF("������Ч��DOS�ڴ澵�񻺳���\n");
		return 0;
	}
	pDosHeader=(PIMAGE_DOS_HEADER)(pImageBuffer);


	if(*((PDWORD)((DWORD)pImageBuffer+pDosHeader->e_lfanew))!=IMAGE_NT_SIGNATURE){  //����ע�⣺FileBuffer��һ��ָ�룬Ҳ����һ����ַ������ת��ΪDWROD��pDosHeader->e_lfanew���
		OutputDebugStringF("���ļ�������Ч��PE�ļ�");
		return 0;
	}

//	printf("DOS�Ŀ�ʼ��ַ�ǣ�%x\n",pDosHeader);
	//NTͷָ��
	pNTHeaders=(PIMAGE_NT_HEADERS)((DWORD)pDosHeader+pDosHeader->e_lfanew);
//	printf("NT�Ŀ�ʼ��ַ�ǣ�%x\n",pNTHeaders);
    //PEͷָ�����NTͷָ�����
	pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)pDosHeader+pDosHeader->e_lfanew)+4);                          //	pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4);
//	printf("PE�Ŀ�ʼ��ַ�ǣ�%x\n",pPEHeader);
	
	//Ѫ�Ľ�ѵ��һ��ָ�����һ�����������ϵ�ʵ�ʵĴ�С�Ǹ�ָ���ʾ���������͡�ȥ��һ��*����������
	pOptionalHeader=(PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);//ָ���ڼ���ʱ��ؽ���ת��Ϊ����
//	printf("optional�Ŀ�ʼ��ַ�ǣ�%x\n",pOptionalHeader);

	pSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader+pPEHeader->SizeOfOptionalHeader);
//	printf("section��Ŀ�ʼ��ַ�ǣ�%x\n",pSectionHeader);

	
	//����SIZE_OF_IMAGE�������ڴ滺�����Ĵ�С����Ȼÿһ��Ӧ�ó����������϶�ӵ�ж�����4GB�����ڴ棬���ǻ��Ǹ���SIZE FOF IMAGE�������ڴ��С
	PVOID pTempFileBuffer=NULL;
	pTempFileBuffer=malloc(len);
	printf("�ļ��Ĵ�СΪ%x\n\r",len);
	if(pTempFileBuffer==NULL){
		OutputDebugStringF("�µ��ļ�����������ʧ��\r\n");
		free(pTempFileBuffer);
		return 0;
		
	}

	memset(pTempFileBuffer,0,len);

	//��ʼ���ļ����������������񻺳�����  1����һ���������е�ͷ���������񻺳����� DosHeader+NTHeader+SectionHeader
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

	//�ж��ļ��������Ƿ���Ч
	if(pFileBuffer==NULL){
		OutputDebugStringF("�ļ�������ָ����Ч\n");
		return 0;
	}

	//�жϸ��ļ��Ƿ���PE�ļ�
	if(*((PWORD)pFileBuffer)!=IMAGE_DOS_SIGNATURE){
		OutputDebugStringF("������Ч��DOS�ļ�\n");
		return 0;
	}
	pDosHeader=(PIMAGE_DOS_HEADER)(pFileBuffer);
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew))!=IMAGE_NT_SIGNATURE){  //����ע�⣺FileBuffer��һ��ָ�룬Ҳ����һ����ַ������ת��ΪDWROD��pDosHeader->e_lfanew���
		OutputDebugStringF("���ļ�������Ч��PE�ļ�");
		return 0;
	}

//	printf("DOS�Ŀ�ʼ��ַ�ǣ�%x\n",pDosHeader);
	//NTͷָ��
	pNTHeaders=(PIMAGE_NT_HEADERS)((DWORD)pDosHeader+pDosHeader->e_lfanew);
//	printf("NT�Ŀ�ʼ��ַ�ǣ�%x\n",pNTHeaders);
    //PEͷָ�����NTͷָ�����
	pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4);
//	printf("PE�Ŀ�ʼ��ַ�ǣ�%x\n",pPEHeader);
	
	//Ѫ�Ľ�ѵ��һ��ָ�����һ�����������ϵ�ʵ�ʵĴ�С�Ǹ�ָ���ʾ���������͡�ȥ��һ��*����������
	pOptionalHeader=(PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);//ָ���ڼ���ʱ��ؽ���ת��Ϊ����
//	printf("optional�Ŀ�ʼ��ַ�ǣ�%x\n",pOptionalHeader);

	pSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader+pPEHeader->SizeOfOptionalHeader);
//	printf("section��Ŀ�ʼ��ַ�ǣ�%x\n",pSectionHeader);

	
	//����SIZE_OF_IMAGE�������ڴ滺�����Ĵ�С����Ȼÿһ��Ӧ�ó����������϶�ӵ�ж�����4GB�����ڴ棬���ǻ��Ǹ���SIZE FOF IMAGE�������ڴ��С
	LPVOID pTempImageBuffer=NULL;
	pTempImageBuffer=malloc(pOptionalHeader->SizeOfImage);
	printf("�ļ���sizeofImageΪ%x\n",pOptionalHeader->SizeOfImage);
	if(pTempImageBuffer==NULL){
		OutputDebugStringF("�����ڴ澵���ļ�ʧ��\n");
	}

	memset(pTempImageBuffer,0,pOptionalHeader->SizeOfImage);

	//��ʼ���ļ����������������񻺳�����  1����һ���������е�ͷ���������񻺳����� DosHeader+NTHeader+SectionHeader
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
//���ļ���ȡ���ļ���������
DWORD ReadFileToBuffer(IN LPSTR FilePath,OUT LPVOID* pFileBuffer){

	FILE* pFile=NULL;
	DWORD fileSize=0;
	LPVOID pTempFileBuffer=NULL; 


	pFile=fopen(FilePath,"rb");

	if(!pFile){
		OutputDebugStringF("�޷��򿪸��ļ�\n");
		return 0;
	}
	
	fseek(pFile,0,SEEK_END);

	fileSize=ftell(pFile);
	
	fseek(pFile,0,SEEK_SET);

	//�����ڴ�ռ�
	pTempFileBuffer=malloc(fileSize);
	
	//ǿ����Ŀռ��ʼ��Ϊ0
	memset(pTempFileBuffer,0,fileSize);
	if(!pTempFileBuffer){
		OutputDebugStringF("����ռ�ʧ��\n");
		fclose(pFile);
		return 0;
	}
	
	int n=fread(pTempFileBuffer,fileSize,1,pFile);

	if(!n){
		OutputDebugStringF("��ȡ�ļ�ʧ��\n");
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
//��PE�ļ�ͷ����Ľڱ���ǰŲ��
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
	
		OutputDebugStringF("�ļ�->������ʧ��\n");
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
	*(PDWORD)((DWORD)pnewbuf+60)=64;//�޸�e_lfanew
	DWORD addrHead_tail=64+4+IMAGE_SIZEOF_FILE_HEADER+pPEHeader->SizeOfOptionalHeader+pPEHeader->NumberOfSections*40+(DWORD)pnewbuf;
	memset((PVOID)addrHead_tail,0,pDosHeader->e_lfanew-64);
	
	*pNewBuffer=pnewbuf;
	pnewbuf=NULL;
//	isOK=MemeryToFile(pnewbuf,len,FILEPATH_OUT);
//	if(isOK){
//		printf("���̳ɹ�");
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
	
		OutputDebugStringF("�ļ�->������ʧ��\n");
		return FALSE;
	}
	pDosHeader=(PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4);
	pOptionHeader=(PIMAGE_OPTIONAL_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader=(PIMAGE_SECTION_HEADER)(((DWORD)pFileBuffer+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER+pPEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER TP_head_end=pSectionHeader+pPEHeader->NumberOfSections;
	//�ж��Ƿ����㹻�Ŀռ��һ���ڱ�
	DWORD lenOfHead=pDosHeader->e_lfanew+4+IMAGE_SIZEOF_FILE_HEADER+pPEHeader->SizeOfOptionalHeader+pPEHeader->NumberOfSections*40;
	printf("ͷ��������ʵ�����ݴ�С��%d\n",lenOfHead);
	if(pOptionHeader->SizeOfHeaders-lenOfHead<80){
		OutputDebugStringF("����������80���ֽ�\n");
		LPVOID pNewFileBuffer=NULL;
		MoveHead(pFileBuffer,&pNewFileBuffer,len);
		free(pFileBuffer);
		pFileBuffer=pNewFileBuffer;
		
	}
	//�ж�����ǳ�����û�ж������ݣ����һ����ĩβ��
	DWORD dwRestData=len-(pSectionHeader[pPEHeader->NumberOfSections-1].PointerToRawData+pSectionHeader[pPEHeader->NumberOfSections-1].SizeOfRawData);
	if(dwRestData>0)
	{
		OutputDebugStringF("��ʣ������\n");
	}
	//������һ���ڵ����
	memcpy(TP_head_end,pSectionHeader,40);
	//���һ������һ���ڳ���0
	TP_head_end++;
	memset(TP_head_end,0,40);
	//�ڵ�������1
	pPEHeader->NumberOfSections++;
	//�޸�sizeofimage
	pOptionHeader->SizeOfImage+=AddSecLen;
	

	//�޸������ڱ��������Ϣ
	TP_head_end--;
	pSectionHeader=pSectionHeader+pPEHeader->NumberOfSections-2;
	TP_head_end->VirtualAddress=NumAlign(pSectionHeader->Misc.VirtualSize,pOptionHeader->SectionAlignment)+pSectionHeader->VirtualAddress;
	TP_head_end->PointerToRawData=NumAlign(pSectionHeader->SizeOfRawData,pOptionHeader->FileAlignment)+pSectionHeader->PointerToRawData+dwRestData;
	TP_head_end->SizeOfRawData=AddSecLen;
	TP_head_end->Misc.VirtualSize=AddSecLen;
	memcpy(TP_head_end->Name,".canaan",strlen(".canaan"));
	OutputDebugStringF("��������Ϣ��\n name:%s\n",TP_head_end->Name);
	
	OutputDebugStringF("virtualSize:%x\n",TP_head_end->Misc.VirtualSize);
	OutputDebugStringF("va:%x\n",TP_head_end->VirtualAddress);
	OutputDebugStringF("sizeofRawData:%x\n",TP_head_end->SizeOfRawData);
	OutputDebugStringF("pointerToRawData:%x\n",TP_head_end->PointerToRawData);
	BOOL addBehind=TRUE;//��Щpe�ļ���ĩβ���˶���������?  û�мӡ����������Լ�����ˡ������Լ�����ӽڵ�ʱ�����ˡ�
	if(addBehind){
		pnewbuf=malloc(len+AddSecLen);
		memset(pnewbuf,0,len+AddSecLen);
		memcpy(pnewbuf,pFileBuffer,len);
		memcpy((LPVOID)((DWORD)pnewbuf+len),pPEBuffer,AddSecLen);
	}else{
		/*
			����ط���Ҳ�����˳���ʲô���ǼӸ�else....
		*/
		pnewbuf=malloc(len);
		memset((PVOID)(TP_head_end->PointerToRawData+(DWORD)pFileBuffer),0,TP_head_end->SizeOfRawData);
		memcpy(pnewbuf,pFileBuffer,len);
	}
	*pNewBuffer=pnewbuf;
	pnewbuf=NULL;
	return TRUE;
}