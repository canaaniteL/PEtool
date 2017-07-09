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
		OutputDebugStringF("读取PE文件错误");
		return;
	}
	this->pDosHeader=(PIMAGE_DOS_HEADER)(this->pFileBuffer);
	this->pNTHeaders=(PIMAGE_NT_HEADERS)((DWORD)(this->pFileBuffer)+pDosHeader->e_lfanew);
	this->pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)(this->pFileBuffer)+pDosHeader->e_lfanew)+4);
	this->pOptionalHeader=(PIMAGE_OPTIONAL_HEADER)(((DWORD)(this->pFileBuffer)+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER);
	this->pSectionHeader=(PIMAGE_SECTION_HEADER)(((DWORD)(this->pFileBuffer)+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER+pPEHeader->SizeOfOptionalHeader);
}
//将文件读取到文件缓冲区中
DWORD PE_Parse::ReadFileToBuffer(IN LPSTR FilePath,OUT LPVOID* pFileBuffer){

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
	this->filelen=fileSize;
	
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

PE_Parse::~PE_Parse()
{

	//释放掉加载的PE file_buffer
	free(this->pFileBuffer);
	this->pFileBuffer=NULL;
}
DWORD PE_Parse::RVAToFOA(DWORD stRVA,PVOID lpFileBuf){
	PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)lpFileBuf;
	DWORD stPEHeadAddr=(DWORD)lpFileBuf+pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNT=(PIMAGE_NT_HEADERS)stPEHeadAddr;
	DWORD dwSectionCount=pNT->FileHeader.NumberOfSections;
	//内存对齐大小
	DWORD dwMemorAli=pNT->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER pSection=(PIMAGE_SECTION_HEADER)(((DWORD)lpFileBuf+pDosHeader->e_lfanew)+4+IMAGE_SIZEOF_FILE_HEADER+pNT->FileHeader.SizeOfOptionalHeader);
	//距离命中节的起始虚拟地址偏移值
	DWORD dwDiffer=0;
	for(DWORD i=0;i<dwSectionCount;i++){
		//sizeofrawdata是文件对齐后的大小，这个大小才是文件拉伸到内存中时要拷贝的大小
		DWORD dwBlockCount=pSection[i].SizeOfRawData/dwMemorAli;
		dwBlockCount+=pSection[i].SizeOfRawData%dwMemorAli?1:0;
		DWORD dwBeginVA=pSection[i].VirtualAddress;
		DWORD dwEndVA=pSection[i].VirtualAddress+dwBlockCount*dwMemorAli;
		//判断如果stRVA在某个区段中
		if(stRVA>=dwBeginVA&&stRVA<dwEndVA){
			dwDiffer=stRVA-dwBeginVA;
			return pSection[i].PointerToRawData+dwDiffer;

		}else if(stRVA<dwBeginVA){//该位置在文件头中，直接返回地址
			
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
	//距离命中节的起始虚拟地址偏移值
	DWORD dwDiffer=0;
	for(DWORD i=0;i<dwSectionCount;i++){
		DWORD FileBeginVA=pSection[i].PointerToRawData;
		DWORD FileEndVA=pSection[i].PointerToRawData+pSection[i].SizeOfRawData;
		//printf("FileBeginVA:%x   FileEndVA:%x  you:%x\n",FileBeginVA,FileEndVA,stRVA);
		//判断如果stRVA在某个区段中
		if(stRVA>=FileBeginVA&&stRVA<FileEndVA){
			dwDiffer=stRVA-FileBeginVA;
			return pSection[i].VirtualAddress+dwDiffer;

		}else if(stRVA<FileBeginVA){//该位置在文件头中，直接返回地址
		
			return stRVA;
		}

	}
	return 0;
}

DWORD PE_Parse::ParImport2Dlg(HWND hDlg)
{
	//往list里面写入节信息
	HWND hListInfo=GetDlgItem(hDlg,IDC_LIST_DLLINFO);
	LV_ITEM vitem;
	//初始化
	memset(&vitem,0,sizeof(LV_ITEM));
	vitem.mask=LVIF_TEXT;
	//pPE_P->RVAToFOA(addr,pPE_P->pFileBuffer);
	PIMAGE_IMPORT_DESCRIPTOR pImport=(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer+RVAToFOA((DWORD)pOptionalHeader->DataDirectory[1].VirtualAddress,pFileBuffer));
	while(pImport->OriginalFirstThunk!=NULL&&pImport->FirstThunk!=NULL){
		//OutputDebugStringF("DLL名：%s\n",(LPSTR)((DWORD)pFileBuffer+RVAToFOA(pImport->Name,pFileBuffer)));
	//	printf("时间戳：%x\n",pImport->TimeDateStamp);
	//	printf("******originalFirstThunk******\n"); 

		//获取DLL的名字
		vitem.pszText=(LPSTR)((DWORD)pFileBuffer+RVAToFOA(pImport->Name,pFileBuffer));
		vitem.iItem=0;          //第几行
		vitem.iSubItem=0;           //第几列
		SendMessage(hListInfo,LVM_INSERTITEM,0,(DWORD)&vitem);  //只有第一列是insertitem,后面的都是setitem

		TCHAR pStrOri[10];
		memset(pStrOri,0,10);
		sprintf(pStrOri,"%08X",pImport->OriginalFirstThunk);

		vitem.pszText=pStrOri;
		vitem.iItem=0;          //第几行
		vitem.iSubItem=1;           //第几列
		SendMessage(hListInfo,LVM_SETITEM,1,(DWORD)&vitem);

		vitem.pszText="xxxx";
		vitem.iItem=0;          //第几行
		vitem.iSubItem=2;           //第几列
		SendMessage(hListInfo,LVM_SETITEM,2,(DWORD)&vitem);

		vitem.pszText="ddd";
		vitem.iItem=0;          //第几行
		vitem.iSubItem=3;           //第几列
		SendMessage(hListInfo,LVM_SETITEM,3,(DWORD)&vitem);

		vitem.pszText="ssss";
		vitem.iItem=0;          //第几行
		vitem.iSubItem=4;           //第几列
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
		//获取选中行            dwRowId为行号
		dwRowId=SendMessage(GetDlgItem(hwnd,IDC_LIST_DLLINFO),LVM_GETNEXTITEM,-1,LVNI_SELECTED);
		if(dwRowId==-1)
		{
			MessageBox(NULL,"出错了啊！","....",MB_OK);
			return true;
		}
		//获取第几列
		lv.iSubItem=1;         //要获取的列
		lv.pszText=strOri;      //指定存储查询结果的缓冲区
		lv.cchTextMax=0x20;    //指定缓冲区大小
		SendMessage(GetDlgItem(hwnd,IDC_LIST_DLLINFO),LVM_GETITEMTEXT,dwRowId,(DWORD)&lv);
		sscanf(strOri,"%x",&OriAddr);
		//根据pid的值调用API函数,并更新modulelist
		//UpdateModuleList(processID);
		OutputDebugStringF( "\nOriAddr: %x \n",OriAddr);
	//	updateApis(OriAddr);


		memset(&lv,0,sizeof(LV_ITEM));
		lv.mask=LVIF_TEXT;
		PDWORD ptunk=(PDWORD)((DWORD)this->pFileBuffer+this->RVAToFOA(OriAddr,this->pFileBuffer));
		while(*ptunk)
		{
			if(*ptunk&0x80000000){
			
				OutputDebugStringF("\n按序号导入   %d\n",(*ptunk)&0x0FFF);
			}else
			{
				PIMAGE_IMPORT_BY_NAME pimportName=(PIMAGE_IMPORT_BY_NAME)((DWORD)this->pFileBuffer+this->RVAToFOA(*ptunk,this->pFileBuffer));
				OutputDebugStringF("\n按名字导入   %x--%s\n",pimportName->Hint,pimportName->Name);

				TCHAR Hint[10];
				memset(Hint,0,10);
				sprintf(Hint,"%04X",pimportName->Hint);

				lv.pszText=Hint;
				lv.iItem=0;          //第几行
				lv.iSubItem=0;           //第几列
				SendMessage(GetDlgItem(hwnd,IDC_LIST_DLL_APINFO),LVM_INSERTITEM,0,(DWORD)&lv);  //只有第一列是insertitem,后面的都是setitem

				lv.pszText=(LPSTR)&(pimportName->Name);
				lv.iItem=0;          //第几行
				lv.iSubItem=1;           //第几列
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

