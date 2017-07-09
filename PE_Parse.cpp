// PE_Parse.cpp: implementation of the PE_Parse class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "PE_Parse.h"
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

PE_Parse::PE_Parse(LPSTR PstrPath)
{
	this->PstrPath=PstrPath;
	getHeaders();
}

void PE_Parse::getHeaders()
{
	DWORD retN=ReadFileToBuffer(this->PstrPath,&(this->pFileBuffer));
	if(!retN){
		OutputDebugStringF("��ȡPE�ļ�����");
		return;
	}
	this->pDosHeader=(PIMAGE_DOS_HEADER)(this->pFileBuffer);
	this->pNTHeaders=(PIMAGE_NT_HEADERS)((DWORD)(this->pFileBuffer)+pDosHeader->e_lfanew);
	this->pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)(this->pFileBuffer)+pDosHeader->e_lfanew)+4);
	this->pOptionalHeader=(PIMAGE_OPTIONAL_HEADER)(((DWORD)(this->pFileBuffer)+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER);
	this->pSectionHeader=(PIMAGE_SECTION_HEADER)(((DWORD)(this->pFileBuffer)+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER+pPEHeader->SizeOfOptionalHeader);
}
//���ļ���ȡ���ļ���������
DWORD PE_Parse::ReadFileToBuffer(IN LPSTR FilePath,OUT LPVOID* pFileBuffer){

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
	this->filelen=fileSize;
	
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

PE_Parse::~PE_Parse()
{

	//�ͷŵ����ص�PE file_buffer
	free(this->pFileBuffer);
	this->pFileBuffer=NULL;
}
DWORD PE_Parse::RVAToFOA(DWORD stRVA,PVOID lpFileBuf){
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)lpFileBuf;
	DWORD stPEHeadAddr=(DWORD)lpFileBuf+pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNT=(PIMAGE_NT_HEADERS)stPEHeadAddr;
	DWORD dwSectionCount=pNT->FileHeader.NumberOfSections;
	//�ڴ�����С
	DWORD dwMemorAli=pNT->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER pSection=(PIMAGE_SECTION_HEADER)(((DWORD)lpFileBuf+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER+pNT->FileHeader.SizeOfOptionalHeader);
	//�������нڵ���ʼ�����ַƫ��ֵ
	DWORD dwDiffer=0;
	for(DWORD i=0;i<dwSectionCount;i++){
		//sizeofrawdata���ļ������Ĵ�С�������С�����ļ����쵽�ڴ���ʱҪ�����Ĵ�С
		DWORD dwBlockCount=pSection[i].SizeOfRawData/dwMemorAli;
		dwBlockCount+=pSection[i].SizeOfRawData%dwMemorAli?1:0;
		DWORD dwBeginVA=pSection[i].VirtualAddress;
		DWORD dwEndVA=pSection[i].VirtualAddress+dwBlockCount*dwMemorAli;
		//�ж����stRVA��ĳ��������
		if(stRVA>=dwBeginVA&&stRVA<dwEndVA){
			dwDiffer=stRVA-dwBeginVA;
			return pSection[i].PointerToRawData+dwDiffer;

		}else if(stRVA<dwBeginVA){//��λ�����ļ�ͷ�У�ֱ�ӷ��ص�ַ
			
			return stRVA;
		}

	}
	return 0;
}

DWORD PE_Parse::FOAToRVA(DWORD stRVA,PVOID lpFileBuf){
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)lpFileBuf;
	DWORD stPEHeadAddr=(DWORD)lpFileBuf+pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNT=(PIMAGE_NT_HEADERS)stPEHeadAddr;
	DWORD dwSectionCount=pNT->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSection=(PIMAGE_SECTION_HEADER)(((DWORD)lpFileBuf+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER+IMAGE_SIZEOF_NT_OPTIONAL32_HEADER);
	//�������нڵ���ʼ�����ַƫ��ֵ
	DWORD dwDiffer=0;
	for(DWORD i=0;i<dwSectionCount;i++){
		DWORD FileBeginVA=pSection[i].PointerToRawData;
		DWORD FileEndVA=pSection[i].PointerToRawData+pSection[i].SizeOfRawData;
		//printf("FileBeginVA:%x   FileEndVA:%x  you:%x\n",FileBeginVA,FileEndVA,stRVA);
		//�ж����stRVA��ĳ��������
		if(stRVA>=FileBeginVA&&stRVA<FileEndVA){
			dwDiffer=stRVA-FileBeginVA;
			return pSection[i].VirtualAddress+dwDiffer;

		}else if(stRVA<FileBeginVA){//��λ�����ļ�ͷ�У�ֱ�ӷ��ص�ַ
		
			return stRVA;
		}

	}
	return 0;
}

DWORD PE_Parse::ParImport2Dlg(HWND hDlg)
{
	//��list����д�����Ϣ
	HWND hListInfo=GetDlgItem(hDlg,IDC_LIST_DLLINFO);
	LV_ITEM vitem;
	//��ʼ��
	memset(&vitem,0,sizeof(LV_ITEM));
	vitem.mask=LVIF_TEXT;
	//pPE_P->RVAToFOA(addr,pPE_P->pFileBuffer);
	PIMAGE_IMPORT_DESCRIPTOR pImport=(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer+RVAToFOA((DWORD)pOptionalHeader->DataDirectory[1].VirtualAddress,pFileBuffer));
	while(pImport->OriginalFirstThunk!=NULL&&pImport->FirstThunk!=NULL){
		//OutputDebugStringF("DLL����%s\n",(LPSTR)((DWORD)pFileBuffer+RVAToFOA(pImport->Name,pFileBuffer)));
	//	printf("ʱ�����%x\n",pImport->TimeDateStamp);
	//	printf("******originalFirstThunk******\n"); 

		//��ȡDLL������
		vitem.pszText=(LPSTR)((DWORD)pFileBuffer+RVAToFOA(pImport->Name,pFileBuffer));
		vitem.iItem=0;          //�ڼ���
		vitem.iSubItem=0;           //�ڼ���
		SendMessage(hListInfo,LVM_INSERTITEM,0,(DWORD)&vitem);  //ֻ�е�һ����insertitem,����Ķ���setitem

		TCHAR pStrOri[10];
		memset(pStrOri,0,10);
		sprintf(pStrOri,"%08X",pImport->OriginalFirstThunk);

		vitem.pszText=pStrOri;
		vitem.iItem=0;          //�ڼ���
		vitem.iSubItem=1;           //�ڼ���
		SendMessage(hListInfo,LVM_SETITEM,1,(DWORD)&vitem);

		vitem.pszText="xxxx";
		vitem.iItem=0;          //�ڼ���
		vitem.iSubItem=2;           //�ڼ���
		SendMessage(hListInfo,LVM_SETITEM,2,(DWORD)&vitem);

		vitem.pszText="ddd";
		vitem.iItem=0;          //�ڼ���
		vitem.iSubItem=3;           //�ڼ���
		SendMessage(hListInfo,LVM_SETITEM,3,(DWORD)&vitem);

		vitem.pszText="ssss";
		vitem.iItem=0;          //�ڼ���
		vitem.iSubItem=4;           //�ڼ���
		SendMessage(hListInfo,LVM_SETITEM,4,(DWORD)&vitem);
		pImport++;

	}
	return 1;

}
DWORD PE_Parse::ParImportClick(HWND hwnd)
{
		//EnumModules(GetDlgItem(hwnd,IDC_LIST_PROCESS),wParam,lParam);
		DWORD dwRowId;
		TCHAR strOri[0x20];
		LV_ITEM lv;

		memset(&lv,0,sizeof(LV_ITEM));
		memset(strOri,0,0x20);
		DWORD OriAddr;
		//��ȡѡ����            dwRowIdΪ�к�
		dwRowId=SendMessage(GetDlgItem(hwnd,IDC_LIST_DLLINFO),LVM_GETNEXTITEM,-1,LVNI_SELECTED);
		if(dwRowId==-1)
		{
			MessageBox(NULL,"�����˰���","....",MB_OK);
			return true;
		}
		//��ȡ�ڼ���
		lv.iSubItem=1;         //Ҫ��ȡ����
		lv.pszText=strOri;      //ָ���洢��ѯ����Ļ�����
		lv.cchTextMax=0x20;    //ָ����������С
		SendMessage(GetDlgItem(hwnd,IDC_LIST_DLLINFO),LVM_GETITEMTEXT,dwRowId,(DWORD)&lv);
		sscanf(strOri,"%x",&OriAddr);
		//����pid��ֵ����API����,������modulelist
		//UpdateModuleList(processID);
		OutputDebugStringF( "\nOriAddr: %x \n",OriAddr);
	//	updateApis(OriAddr);


		memset(&lv,0,sizeof(LV_ITEM));
		lv.mask=LVIF_TEXT;
		PDWORD ptunk=(PDWORD)((DWORD)this->pFileBuffer+this->RVAToFOA(OriAddr,this->pFileBuffer));
		while(*ptunk)
		{
			if(*ptunk&0x80000000){
			
				OutputDebugStringF("\n����ŵ���   %d\n",(*ptunk)&0x0FFF);
			}else
			{
				PIMAGE_IMPORT_BY_NAME pimportName=(PIMAGE_IMPORT_BY_NAME)((DWORD)this->pFileBuffer+this->RVAToFOA(*ptunk,this->pFileBuffer));
				OutputDebugStringF("\n�����ֵ���   %x--%s\n",pimportName->Hint,pimportName->Name);

				TCHAR Hint[10];
				memset(Hint,0,10);
				sprintf(Hint,"%04X",pimportName->Hint);

				lv.pszText=Hint;
				lv.iItem=0;          //�ڼ���
				lv.iSubItem=0;           //�ڼ���
				SendMessage(GetDlgItem(hwnd,IDC_LIST_DLL_APINFO),LVM_INSERTITEM,0,(DWORD)&lv);  //ֻ�е�һ����insertitem,����Ķ���setitem

				lv.pszText=(LPSTR)&(pimportName->Name);
				lv.iItem=0;          //�ڼ���
				lv.iSubItem=1;           //�ڼ���
				SendMessage(GetDlgItem(hwnd,IDC_LIST_DLL_APINFO),LVM_SETITEM,1,(DWORD)&lv);	
			}
			

			ptunk++;
		}
		



		return 1;

}
DWORD PE_Parse::ParRelocTree(HWND hwnd)
{


	TV_ITEM item;  
	item.mask = TVIF_TEXT | TVIF_PARAM;  
	item.cchTextMax = 2;  
	item.pszText = "C: ";  
  
	TV_INSERTSTRUCT insert;  
	insert.hParent = TVI_ROOT;  
	insert.hInsertAfter = TVI_LAST;  
	insert.item = item;  
  
	HTREEITEM hParent;  
	hParent=(HTREEITEM)SendMessage(GetDlgItem(hwnd,IDC_TREE_RESOURCE),TVM_INSERTITEM,0,(LPARAM)&insert);

	item.pszText = "windows";  
	item.cchTextMax = 7;  
	insert.hParent = hParent;  
	insert.item = item;  
	hParent=(HTREEITEM)SendMessage(GetDlgItem(hwnd,IDC_TREE_RESOURCE),TVM_INSERTITEM,0,(LPARAM)&insert);

	item.pszText = "windows2";  
	item.cchTextMax = 7;  
	insert.hParent = TVI_ROOT;  
	insert.item = item;  
	hParent=(HTREEITEM)SendMessage(GetDlgItem(hwnd,IDC_TREE_RESOURCE),TVM_INSERTITEM,0,(LPARAM)&insert); 
	return 1;
}

