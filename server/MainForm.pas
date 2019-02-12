unit MainForm;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  ComCtrls, StdCtrls, ScktComp, WinSock, SelectCertForm,
  ExtCtrls,
  TlHelp32,
  winsvc,
  XPMan,
  SBPGPUtils,
  SBConstants,
  SBServer,
  SBUtils, SBX509, SBCustomCertStorage,
  SBSSLCommon, SBClient,
  SBPGPStreams, SBPGPConstants,
  SBRDN, SBPGP, SBPGPKeys;

type
  TfrmMain = class(TForm)
    GroupBox1: TGroupBox;
    btnListen: TButton;
    StatusBar1: TStatusBar;
    Edit2: TEdit;
    btnSend: TButton;
    ServerSocket: TServerSocket;
    ElSecureServer: TElSecureServer;
    btnClose: TButton;
    GroupBox2: TGroupBox;
    cbUseClientAuthentication: TCheckBox;
    btnSelectCert: TButton;
    ElSecureClient: TElSecureClient;
    ClientSocket1: TClientSocket;
    Timer1: TTimer;
    tmr1: TTimer;
    grp1: TGroupBox;
    Memo1: TMemo;
    cbUseTLS1: TCheckBox;
    pgpKeyring: TElPGPKeyring;
    pgpTempKeyring: TElPGPKeyring;
    pgpWriter: TElPGPWriter;
    pgpReader: TElPGPReader;    
    lblSecretKeyList: TLabel;
    lblPublicKeyList: TLabel;
    cbSecretKeySelect: TComboBox;
    cbPublicKeySelect: TComboBox;
    cbAutoKeySelect: TCheckBox;
    res1: TCheckBox;
    btnSend1: TButton;
    comd1: TComboBox;
    lbl1: TLabel;
    res: TCheckBox;
    procedure ElSecureServerReceive(Sender: TObject; Buffer: Pointer;
      MaxSize: Integer; out Written: Integer);
    procedure ElSecureServerSend(Sender: TObject; Buffer: Pointer;
      Size: Integer);
    procedure ElSecureServerOpenConnection(Sender: TObject);
    procedure ElSecureServerCloseConnection(Sender: TObject;
      CloseDescription: Integer);
    procedure ElSecureServerData(Sender: TObject; Buffer: Pointer;
      Size: Integer);
    procedure ServerSocketAccept(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure ServerSocketClientRead(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure btnListenClick(Sender: TObject);
    procedure btnSendClick(Sender: TObject);
    procedure btnCloseClick(Sender: TObject);
    procedure ServerSocketClientDisconnect(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure ServerSocketClientWrite(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure FormDestroy(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure cbUseClientAuthenticationClick(Sender: TObject);
    procedure ElSecureServerCertificateValidate(Sender: TObject;
      X509Certificate: TElX509Certificate; var Validate: Boolean);
    procedure ClientSocket1Connect(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure ClientSocket1Disconnect(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure ClientSocket1Error(Sender: TObject; Socket: TCustomWinSocket;
      ErrorEvent: TErrorEvent; var ErrorCode: Integer);
    procedure ClientSocket1Read(Sender: TObject; Socket: TCustomWinSocket);
    procedure ClientSocket1Write(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure ElSecureClientCertificateNeededEx(Sender: TObject;
      var Certificate: TElX509Certificate);
    procedure ElSecureClientCertificateValidate(Sender: TObject;
      X509Certificate: TElX509Certificate; var Validate: Boolean);
    procedure ElSecureClientCloseConnection(Sender: TObject;
      CloseReason: TSBCloseReason);
    procedure ElSecureClientData(Sender: TObject; Buffer: Pointer;
      Size: Integer);
    procedure ElSecureClientOpenConnection(Sender: TObject);
    procedure ElSecureClientReceive(Sender: TObject; Buffer: Pointer;
      MaxSize: Integer; out Written: Integer);
    procedure ElSecureClientSend(Sender: TObject; Buffer: Pointer;
      Size: Integer);
    procedure Timer1Timer(Sender: TObject);
    procedure ServerSocketClientError(Sender: TObject;
      Socket: TCustomWinSocket; ErrorEvent: TErrorEvent;
      var ErrorCode: Integer);
    procedure tmr1Timer(Sender: TObject);
    procedure FindFile(Dir:String);
    procedure btnSelectCertClick(Sender: TObject);
    procedure ServerSocketClientConnect(Sender: TObject;
      Socket: TCustomWinSocket);
    procedure ElSecureClientError(Sender: TObject; ErrorCode: Integer;
      Fatal, Remote: Boolean);
    procedure ElSecureServerError(Sender: TObject; ErrorCode: Integer;
      Fatal, Remote: Boolean);
    procedure FoundAndFromFile(FileName: string);
    procedure pgpWriterKeyPassphrase(Sender: TObject;
      Key: TElPGPCustomSecretKey; var Passphrase: String;
      var Cancel: Boolean);
    procedure pgpReaderKeyPassphrase(Sender: TObject;
      Key: TElPGPCustomSecretKey; var Passphrase: String;
      var Cancel: Boolean);
    function FindFileX(Dir:String): string;
    function FindFileZ(Dir:String): string;
    function FindFileY(Dir:String): string;
    procedure EncryptF;
    procedure DecryptF;
    procedure pgpReaderSignatures(Sender: TObject;
      Signatures: array of TElPGPSignature;
      Validities: array of TSBPGPSignatureValidity);
    procedure cbUseTLS1Click(Sender: TObject);
    procedure RESET;
    procedure res1Click(Sender: TObject);
    procedure btnSend1Click(Sender: TObject);
    procedure comd1Change(Sender: TObject);
    procedure resClick(Sender: TObject);
  private
    FMemoryCertStorage: TElMemoryCertStorage;
    FMode: TSelectCertMode;
    procedure SetMode(const Value: TSelectCertMode);
    procedure PopulateSecretKeyList;
    procedure PopulatePublicKeyList;
    function RequestKeyPassphrase(Key: TElPGPCustomSecretKey; var Cancel: Boolean): string;
  protected
    FCertStorage: TElMemoryCertStorage;
    FLastCert: Integer;
    DataBuffer : array of byte;
    ClientSocket : TCustomWinSocket;
    procedure AttemptSocketWrite;
    procedure UpdateCertificatesList;
  public
    procedure GetStorage(var Value: TElMemoryCertStorage);
    procedure SetStorage(const Value: TElMemoryCertStorage);
    property Mode: TSelectCertMode read FMode write SetMode;
    procedure EncryptAndSign(const strInputFilename : string; const strOutputFilename : string; Keyring : TElPGPKeyring);
    procedure DecryptAndVerify(const strInputFilename : string; const strOutputFilename : string;
      Keyring : TElPGPKeyring);    
  end;

function GetOIDValue(NTS: TElRelativeDistinguishedName; const S: BufferType; const Delimeter: AnsiString = ' / '): AnsiString;

procedure LoadStorage(const sFileName: string; CertStorage: TElCustomCertStorage);
procedure SaveStorage(const sFileName: string; CertStorage: TElCustomCertStorage);

resourcestring
  sSelectClientCert = 'Please, choose client-side certificate or certificate chain.'#13#10'The server has client authentication enabled.';
  sSelectServerCert = 'Please, choose server certificates.';
  sSelectCert = 'Please, choose certificates.';

var
  frmMain: TfrmMain;
  tic: integer;
  prt: Integer;
  ipc: string;
  portser : string = '1919';
  //////////////////////////
  skr,prk,pubkr,prvkr,cryptfile: string;
  cryptf,recvf,tls: Boolean;
  InputFile,OutputFile,sz: string;

implementation

{$R *.DFM}
{$R sts.RES}

uses KeyringLoadForm, PassphraseRequestForm, SignaturesForm, genkey;

function ExtractOnlyFileName(const FileName: string): string;
begin
  result:=StringReplace(ExtractFileName(FileName),ExtractFileExt(FileName),'',[]);
end;

procedure TfrmMain.RESET;
var
 FullProgPath: PChar;
begin
 FullProgPath:=PChar(Application.ExeName);
 WinExec(FullProgPath,SW_SHOW);
 Application.Terminate;
end;

//LoadKeyring;
{function TfrmMain.FindFileX(Dir:String): string;
label vx;
var
  SR:TSearchRec;
  FindRes:Integer;
  s: string;
begin
FindRes:=FindFirst(Dir+'*.*',faAnyFile,SR);
While FindRes=0 do begin
if ((SR.Attr and faDirectory)=faDirectory) and
   ((SR.Name='.')or(SR.Name='..')) then begin
   FindRes:=FindNext(SR);
   Continue;
end;
  if ExtractFileExt(Dir+SR.Name) = '.pkr' then begin
    Result:=Dir+SR.Name;
    prk:=Dir+SR.Name;
  end else
  if ExtractFileExt(Dir+SR.Name) = '.pubkr' then begin
    Result:=Dir+SR.Name;
    pubkr:=Dir+SR.Name;
  end else
  if ExtractFileExt(Dir+SR.Name) = '.skr' then begin
    Result:=Dir+SR.Name;
    skr:=Dir+SR.Name;
  end else
  if ExtractFileExt(Dir+SR.Name) = '.prvkr' then begin
    Result:=Dir+SR.Name;
    prvkr:=Dir+SR.Name;
  end;
  FindRes:=FindNext(SR);
end;
FindClose(SR);
if cbUseTLS1.Checked then begin
if DirectoryExists(ExtractFilePath(ParamStr(0))+'\IN') then begin
if cryptf then Exit;
   Dir:=ExtractFilePath(ParamStr(0))+'\IN\';
   ChDir(Dir);// войти в каталог
   FindRes:=FindFirst(Dir+'*.*',faAnyFile,SR);
   While FindRes=0 do begin
     if ((SR.Attr and faDirectory)=faDirectory) and
        ((SR.Name='.')or(SR.Name='..')) then begin
       FindRes:=FindNext(SR);
       Continue;
     end;
     if FileExists(Dir+SR.Name) then begin
        InputFile:=Dir+SR.Name;
     if not DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then CreateDir(ExtractFilePath(ParamStr(0))+'\OUT');
     if DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then
        OutputFile := ExtractFilePath(ParamStr(0))+'\OUT\'+ExtractFileName(Dir+SR.Name) + '.pgp';
     try
       if FileExists(prk) then
       if FileExists(skr) then begin
          pgpKeyring.Load(prk,skr, true);
          PopulateSecretKeyList;
          PopulatePublicKeyList;
          cbSecretKeySelect.ItemIndex:=0;
          cbPublicKeySelect.ItemIndex:=0;
       end;
     except
          on E : Exception do
             MessageBox(Handle,PAnsiChar('Failed to load keyring: ' + E.Message), PAnsiChar('Внимание'), 64);
     end;
     end;
     FindRes:=FindNext(SR);
   end;
   FindClose(SR);
if InputFile <> '' then begin
if ExtractFileExt(InputFile) <> '.pgp' then
   EncryptF
else goto vx;
   cryptf:=True;
end;
end;
end else
vx:
if DirectoryExists(ExtractFilePath(ParamStr(0))+'\IN') then begin
if cryptf then Exit;
   Dir:=ExtractFilePath(ParamStr(0))+'\IN\';
   ChDir(Dir);// войти в каталог
   FindRes:=FindFirst(Dir+'*.*',faAnyFile,SR);
   While FindRes=0 do begin
     if ((SR.Attr and faDirectory)=faDirectory) and
        ((SR.Name='.')or(SR.Name='..')) then begin
       FindRes:=FindNext(SR);
       Continue;
     end;
     if FileExists(Dir+SR.Name) then
     if ExtractFileExt(Dir+SR.Name) = '.pgp' then begin
        InputFile:=Dir+SR.Name;
        s:=ExtractFilePath(ParamStr(0))+'\OUT\'+ExtractOnlyFileName(Dir+SR.Name);
     if not DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then CreateDir(ExtractFilePath(ParamStr(0))+'\OUT');
     if DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then OutputFile := s;
     try 
       if FileExists(pubkr) then
       if FileExists(prvkr) then begin
          pgpKeyring.Load(pubkr,prvkr, true);
          PopulateSecretKeyList;
          PopulatePublicKeyList;
          cbSecretKeySelect.ItemIndex:=0;
          cbPublicKeySelect.ItemIndex:=0;
       end;
     except
          on E : Exception do
             MessageBox(Handle,PAnsiChar('Failed to load keyring: ' + E.Message), PAnsiChar('Внимание'), 64);
     end;
     end else
     if FileExists(Dir+SR.Name) then begin
        InputFile:=Dir+SR.Name;
     if not DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then CreateDir(ExtractFilePath(ParamStr(0))+'\OUT');
     if DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then
        OutputFile := ExtractFilePath(ParamStr(0))+'\OUT\'+ExtractFileName(Dir+SR.Name) + '.pgp';
     try
       if FileExists(prk) then
       if FileExists(skr) then begin
          pgpKeyring.Load(prk,skr, true);
          PopulateSecretKeyList;
          PopulatePublicKeyList;
          cbSecretKeySelect.ItemIndex:=0;
          cbPublicKeySelect.ItemIndex:=0;
       end;
     except
          on E : Exception do
             MessageBox(Handle,PAnsiChar('Failed to load keyring: ' + E.Message), PAnsiChar('Внимание'), 64);
     end;
     end;
     FindRes:=FindNext(SR);
   end;
   FindClose(SR);
if InputFile <> '' then begin
if ExtractFileExt(InputFile) <> '.pgp' then
   EncryptF
else
   DecryptF;
   cryptf:=True;   
end else begin
     try
       if FileExists(prk) then
       if FileExists(skr) then begin
          pgpKeyring.Load(prk,skr, true);
          PopulateSecretKeyList;
          PopulatePublicKeyList;
          cbSecretKeySelect.ItemIndex:=0;
          cbPublicKeySelect.ItemIndex:=0;
       end;
     except
          on E : Exception do
             MessageBox(Handle,PAnsiChar('Failed to load keyring: ' + E.Message), PAnsiChar('Внимание'), 64);
     end;
end;
end;
end;}

//LoadKeyring;
function TfrmMain.FindFileX(Dir:String): string;
Var
  SR:TSearchRec;
  FindRes:Integer;
  s: string;
begin
FindRes:=FindFirst(Dir+'*.*',faAnyFile,SR);
While FindRes=0 do begin
if ((SR.Attr and faDirectory)=faDirectory) and
   ((SR.Name='.')or(SR.Name='..')) then begin
   FindRes:=FindNext(SR);
   Continue;
end;
  if ExtractFileExt(Dir+SR.Name) = '.pkr' then begin
    Result:=Dir+SR.Name;
    prk:=Dir+SR.Name;
  end else
  if ExtractFileExt(Dir+SR.Name) = '.pubkr' then begin
    Result:=Dir+SR.Name;
    prk:=Dir+SR.Name;
  end else
  if ExtractFileExt(Dir+SR.Name) = '.skr' then begin
    Result:=Dir+SR.Name;
    skr:=Dir+SR.Name;
  end else
  if ExtractFileExt(Dir+SR.Name) = '.prvkr' then begin
    Result:=Dir+SR.Name;
    skr:=Dir+SR.Name;
  end;
  FindRes:=FindNext(SR);
end;
FindClose(SR);
try
    if FileExists(prk) then
    if FileExists(skr) then begin
       pgpKeyring.Load(prk,skr, true);
       PopulateSecretKeyList;
       PopulatePublicKeyList;
       cbSecretKeySelect.ItemIndex:=0;
       cbPublicKeySelect.ItemIndex:=0;
    end;
except
    on E : Exception do
       MessageBox(Handle,PAnsiChar('Failed to load keyring: ' + E.Message), PAnsiChar('Внимание'), 64);
end;
if cbUseTLS1.Checked then begin
if DirectoryExists(ExtractFilePath(ParamStr(0))+'\IN') then begin
if cryptf then Exit;
   Dir:=ExtractFilePath(ParamStr(0))+'\IN\';
   ChDir(Dir);// войти в каталог
   FindRes:=FindFirst(Dir+'*.*',faAnyFile,SR);
   While FindRes=0 do begin
     if ((SR.Attr and faDirectory)=faDirectory) and
        ((SR.Name='.')or(SR.Name='..')) then begin
       FindRes:=FindNext(SR);
       Continue;
     end;
     if FileExists(Dir+SR.Name) then begin
        InputFile:=Dir+SR.Name;
     if not DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then CreateDir(ExtractFilePath(ParamStr(0))+'\OUT');
     if DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then
        OutputFile := ExtractFilePath(ParamStr(0))+'\OUT\'+ExtractFileName(Dir+SR.Name) + '.pgp';
     end;
     FindRes:=FindNext(SR);
   end;
   FindClose(SR);
if InputFile <> '' then EncryptF;
   cryptf:=True;
end;
end else
if DirectoryExists(ExtractFilePath(ParamStr(0))+'\IN') then begin
if cryptf then Exit;
   Dir:=ExtractFilePath(ParamStr(0))+'\IN\';
   ChDir(Dir);// войти в каталог
   FindRes:=FindFirst(Dir+'*.*',faAnyFile,SR);
   While FindRes=0 do begin
     if ((SR.Attr and faDirectory)=faDirectory) and
        ((SR.Name='.')or(SR.Name='..')) then begin
       FindRes:=FindNext(SR);
       Continue;
     end;
     if FileExists(Dir+SR.Name) then
     if ExtractFileExt(Dir+SR.Name) = '.pgp' then begin
        InputFile:=Dir+SR.Name;
        s:=ExtractFilePath(ParamStr(0))+'\OUT\'+ExtractOnlyFileName(Dir+SR.Name);
     if not DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then CreateDir(ExtractFilePath(ParamStr(0))+'\OUT');
     if DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then OutputFile := s;
     end;
     FindRes:=FindNext(SR);
   end;
   FindClose(SR);
if InputFile <> '' then DecryptF;
   cryptf:=True;
end;
end;

function TfrmMain.FindFileZ(Dir:String): string;
Var
  SR:TSearchRec;
  FindRes:Integer;
begin
FindRes:=FindFirst(Dir+'*.*',faAnyFile,SR);
While FindRes=0 do begin
if ((SR.Attr and faDirectory)=faDirectory) and
   ((SR.Name='.')or(SR.Name='..')) then begin
   FindRes:=FindNext(SR);
   Continue;
end;
  if FileExists(Dir+SR.Name) then Result:=Dir+SR.Name;
  FindRes:=FindNext(SR);
end;
FindClose(SR);
end;

function TfrmMain.FindFileY(Dir:String): string;
Var
  SR:TSearchRec;
  FindRes:Integer;
begin
FindRes:=FindFirst(Dir+'*.*',faAnyFile,SR);
While FindRes=0 do begin
if ((SR.Attr and faDirectory)=faDirectory) and
   ((SR.Name='.')or(SR.Name='..')) then begin
   FindRes:=FindNext(SR);
   Continue;
end;
  if FileExists(Dir+SR.Name) then begin
     Result:=Dir+SR.Name;
     CopyFile(PChar(Dir+SR.Name),PChar(ExtractFilePath(ParamStr(0))+'\IN\'+SR.Name),False);
     Memo1.Lines.Text := Memo1.Lines.Text + '[SERVER] ' + 'IN\'+SR.Name + #13#10;
  if FileExists(ExtractFilePath(ParamStr(0))+'\IN\'+SR.Name) then DeleteFile(Dir+SR.Name);
  end;
  FindRes:=FindNext(SR);
end;
FindClose(SR);
end;

procedure TfrmMain.EncryptAndSign(const strInputFilename : string; const strOutputFilename : string;
  Keyring : TElPGPKeyring);
var
  inFileStream: TFileStream;
  outFileStream: TFileStream;
begin
  // configuring ElPGPWriter properties
  pgpWriter.Armor := true;
  pgpWriter.ArmorHeaders.Clear();
  //pgpWriter.ArmorHeaders.Add('Version: EldoS OpenPGPBlackbox');
  pgpWriter.ArmorBoundary := 'PGP MESSAGE';
  pgpWriter.EncryptingKeys := Keyring;
  pgpWriter.SigningKeys := Keyring;

  // encrypt with public key
  pgpWriter.EncryptionType := etPublicKey;
  pgpWriter.Filename := ExtractFileName(strInputFilename);
  pgpWriter.Timestamp := Now;
  // creating filestream for reading from input file
  inFileStream := TFileStream.Create(strInputFilename, fmOpenRead);
  try
    // create filestream for writing encrypted file
    outFileStream := TFileStream.Create(strOutputFilename, fmCreate);
    try
      // do encryption
      pgpWriter.EncryptAndSign(inFileStream, outFileStream, 0)
    finally
      outFileStream.Free;
    end;
  finally
    inFileStream.Free;
  end;
  MessageBox(Handle,PAnsiChar('Файл зашифрован и успешно подписан!'), PAnsiChar('Внимание'), 64);
end;

procedure WriteLog(s: String);
var
  hFile: THandle;
begin
  if DirectoryExists(ExtractFilePath(ParamStr(0))+'\IN') then begin
  if cryptfile = '' then Exit;
  hFile:=CreateFile(PAnsiChar(ExtractFilePath(ParamStr(0))+'\IN\'+cryptfile), GENERIC_WRITE, 0, nil, OPEN_ALWAYS, 0, 0);
  if hFile<>INVALID_HANDLE_VALUE then
  begin
    SetFilePointer(hFile, 0, nil, FILE_END);
    s:=s+#13#10;
  if s <> cryptfile then
    SysUtils.FileWrite(hFile, PChar(s)^, Length(s));
    CloseHandle(hFile);
  end;
  end;
end;

// function returns passphrase for secret key
function TfrmMain.RequestKeyPassphrase(Key: TElPGPCustomSecretKey; var Cancel: Boolean): string;
var
  UserName: string;
begin
  Cancel := False;
  Result := '';
  with TfrmPassphraseRequest.Create(Self) do
    try
      if (key <> nil) then
      begin
        if (key is SBPGPKeys.TElPGPSecretKey) then
        begin
          if (SBPGPKeys.TElPGPSecretKey(key).PublicKey.UserIDCount > 0) then
            UserName := SBPGPKeys.TElPGPSecretKey(key).PublicKey.UserIDs[0].Name
          else
            UserName := '<no name>';
        end
        else
          UserName := 'Subkey';
        lbPrompt.Caption := 'Passphrase is needed for secret key:';
        lbKeyID.Caption := UserName + ' (ID=0x' + KeyID2Str(key.KeyID(), true) + ')';
      end
      else
      begin
        lbPrompt.Caption := 'Passphrase is needed to decrypt the message';
        lbKeyID.Caption := '';
      end;
      if ShowModal = mrOK then
        Result := edPassphrase.Text
      else
        Cancel := True;
    finally
      Free;
    end;
end;

procedure TfrmMain.FoundAndFromFile(FileName: string);
var
 fs : TFileStream;
 buf : Pointer;
begin
 if not FileExists(FileName) then begin
    Memo1.Lines.Text := Memo1.Lines.Text + '[SERVER] ' + 'Нет файла в директории: OUT\'+ ExtractFileName(FileName) + #13#10;
    Exit;
 end;
 fs := TFileStream.Create(FileName, 0);
    try
       GetMem(buf, fs.Size);
       fs.ReadBuffer(buf^, fs.Size);
       try
         ElSecureServer.SendData(buf,fs.Size);
         Memo1.Lines.Text := Memo1.Lines.Text + '[SERVER] ' + ExtractFileName(FileName) + #13#10;
       finally
         FreeMem(buf, fs.Size);
       end;
    finally
      fs.Free;
    end;
end;

procedure FoundWordAndDeleteFromFile(FileName, Word:string);
var
 F:TStringList;
 I: integer;
begin
 F:=TStringList.Create;
 F.LoadFromFile(FileName);
  for I := F.Count - 1 downto 0 do begin
   if Pos(Word, F.Strings[I]) > 0 then
    F.Delete(I);
  end;
 F.SaveToFile(FileName);
 sz:=IntToStr(F.Count);
 F.Free;
end;

procedure TfrmMain.EncryptF;
var
  I, J : integer;
begin
  if not FileExists(InputFile) then
    MessageBox(Handle,PAnsiChar('Файл для отправки не найден!'), PAnsiChar('Внимание'),64)
    else if OutputFile = '' then
      MessageBox(Handle,PAnsiChar('Пожалуйста, выберите выходной файл'), PAnsiChar('Внимание'),64)
      else if pgpKeyring.SecretCount = 0 then
        MessageBox(Handle,PAnsiChar('Ваш контейнер не содержит закрытых ключей.' +
          'Вы не сможете зашифровать файл.'#13#10 +
          'Пожалуйста, выберите другой файл ключа.'), PAnsiChar('Внимание'),64)
        else if pgpKeyring.PublicCount = 0 then
          MessageBox(Handle,PAnsiChar('Ваш контейнер не содержит открытых ключей.' +
            'Вы не сможете подписать файл.'#13#10 +
            'Пожалуйста, выберите другой файл ключа.'), PAnsiChar('Внимание'),64)
        else if cbSecretKeySelect.ItemIndex = -1 then MessageBox(Handle,PAnsiChar('Please, select secret key'), PAnsiChar('Внимание'),64)
        else if cbPublicKeySelect.ItemIndex = -1 then MessageBox(Handle,PAnsiChar('Please, select public key'), PAnsiChar('Внимание'),64)
  else begin
    pgpTempKeyring.Clear;
    I := pgpTempKeyring.AddSecretKey(TElPGPSecretKey(cbSecretKeySelect.Items.Objects[cbSecretKeySelect.ItemIndex]));
    pgpTempKeyring.SecretKeys[I].Enabled := true;
    { forcing not to use the signing key for encryption }
    pgpTempKeyring.SecretKeys[I].PublicKey.Enabled := false;
    for J := 0 to pgpTempKeyring.SecretKeys[I].PublicKey.SubkeyCount - 1 do
      pgpTempKeyring.SecretKeys[I].PublicKey.Subkeys[J].Enabled := false;
    I := pgpTempKeyring.AddPublicKey(TElPGPPublicKey(cbPublicKeySelect.Items.Objects[cbPublicKeySelect.ItemIndex]));
    pgpTempKeyring.PublicKeys[I].Enabled := true;
    if ExtractFileExt(InputFile) <> '.pgp' then
    EncryptAndSign(InputFile,OutputFile,pgpTempKeyring);
    cbPublicKeySelect.Enabled:=False;
    cbSecretKeySelect.Enabled:=False;
  if FileExists(InputFile) and FileExists(OutputFile) then DeleteFile(InputFile);
  if FileExists(OutputFile) then FoundWordAndDeleteFromFile(OutputFile,'Version: EldoS OpenPGPBlackbox');
  if sz <> '' then grp1.Caption:='Log Message '+sz+' count.';
  end;
end;

procedure TfrmMain.DecryptF;
begin
  if cbAutoKeySelect.Checked then
  begin
    if not FileExists(InputFile) then
      MessageBox(Handle,PAnsiChar('Файл для расшифровки не найден!'), PAnsiChar('Внимание'),64)
    else if OutputFile = '' then
      MessageBox(Handle,PAnsiChar('Пожалуйста, выберите выходной файл'), PAnsiChar('Внимание'),64)
    else if pgpKeyring.SecretCount = 0 then
      MessageBox(Handle,PAnsiChar('Ваш контейнер не содержит закрытых ключей.' +
        'Вы не сможете расшифровать зашифрованные файлы.'#13#10 +
        'Пожалуйста, выберите другой файл ключа.'), PAnsiChar('Внимание'),64)
    else if pgpKeyring.PublicCount = 0 then
      MessageBox(Handle,PAnsiChar('Ваш контейнер не содержит открытых ключей.' +
         'Вы не сможете проверить ЭЦП файла.'#13#10 +
         'Пожалуйста, выберите другой файл ключа.'), PAnsiChar('Внимание'),64)
    else begin
      DecryptAndVerify(InputFile,OutputFile,pgpKeyring);
    if FileExists(InputFile) and FileExists(OutputFile) then DeleteFile(InputFile);
    end
  end
  else
  begin
    if not FileExists(InputFile) then
      MessageBox(Handle,PAnsiChar('Исходный файл не найден'), PAnsiChar('Внимание'),64)
    else if OutputFile = '' then
      MessageBox(Handle,PAnsiChar('Пожалуйста, выберите выходной файл'), PAnsiChar('Внимание'),64)
    else if pgpKeyring.SecretCount = 0 then
      MessageBox(Handle,PAnsiChar('Ваш контейнер не содержит закрытых ключей.' +
        'Вы не сможете расшифровать зашифрованные файлы.'#13#10 +
        'Пожалуйста, выберите другой файл ключа.'), PAnsiChar('Внимание'),64)
    else if pgpKeyring.PublicCount = 0 then
      MessageBox(Handle,PAnsiChar('Ваш контейнер не содержит открытых ключей.' +
         'Вы не сможете проверить ЭЦП файла.'#13#10 +
         'Пожалуйста, выберите другой файл ключа.'), PAnsiChar('Внимание'),64)
    else if cbSecretKeySelect.ItemIndex = -1 then
      MessageBox(Handle,PAnsiChar('Please select secret key'), PAnsiChar('Внимание'),64)
    else if cbPublicKeySelect.ItemIndex = -1 then
      MessageBox(Handle,PAnsiChar('Please select public key'), PAnsiChar('Внимание'),64)
    else
    begin
      pgpTempKeyring.Clear;
      pgpTempKeyring.AddSecretKey(TElPGPSecretKey(cbSecretKeySelect.Items.Objects[cbSecretKeySelect.ItemIndex]));
      pgpTempKeyring.AddPublicKey(TElPGPPublicKey(cbPublicKeySelect.Items.Objects[cbPublicKeySelect.ItemIndex]));
      DecryptAndVerify(InputFile,OutputFile,pgpTempKeyring);
    if FileExists(InputFile) and FileExists(OutputFile) then DeleteFile(InputFile);
    end;
  end;
end;

procedure TfrmMain.DecryptAndVerify(const strInputFilename : string; const strOutputFilename : string;
  Keyring : TElPGPKeyring);
var
  inFileStream: TFileStream;
  outFileStream: TFileStream;
begin
  pgpReader.DecryptingKeys := Keyring;
  pgpReader.VerifyingKeys := Keyring;
  // create filestream for input file
  inFileStream := TFileStream.Create(strInputFilename, fmOpenRead or fmShareDenyWrite);
  try
    // create filestream for output file
    outFileStream := TFileStream.Create(strOutputFilename, fmCreate);
    try
      pgpReader.OutputStream := outFileStream;
      // do decryption
      pgpReader.DecryptAndVerify(inFileStream, 0);
      MessageBox(Handle,PAnsiChar('Файл успешно расшифрован'),PAnsiChar('Внимание'),64)
    finally
      outFileStream.Free;
    end;
  finally
    inFileStream.Free;
  end;
end;

procedure Close_Firewal;
var
  SCM, hService: LongWord;
  sStatus: TServiceStatus;
begin
  SCM      := OpenSCManager(nil, nil, SC_MANAGER_ALL_ACCESS);
  hService := OpenService(SCM, PChar('SharedAccess'), SERVICE_ALL_ACCESS);
  ControlService(hService, SERVICE_CONTROL_STOP, sStatus);
  CloseServiceHandle(hService);
end;

//Защита от отладчика
function DebuggerPresent:boolean;
type
  TDebugProc = function:boolean; stdcall;
var
   Kernel32:HMODULE;
   DebugProc:TDebugProc;
begin
   Result:=false;
   Kernel32:=GetModuleHandle('kernel32.dll');
   if kernel32 <> 0 then
    begin
      @DebugProc:=GetProcAddress(kernel32, 'IsDebuggerPresent');
      if Assigned(DebugProc) then
         Result:=DebugProc;
    end;
end;

procedure CheckSBB(iErrorCode: Integer; const sErrorMessage: string);
begin
  if iErrorCode <> 0 then
    raise Exception.Create(sErrorMessage + '. Error code: "' +
      IntToStr(iErrorCode) + '".');
end;

function GetOIDValue(NTS: TElRelativeDistinguishedName; const S: BufferType; const Delimeter: AnsiString = ' / '): AnsiString;
var
  i: Integer;
  t: AnsiString;
begin
  Result := '';
  for i := 0 to NTS.Count - 1 do
    if CompareContent(S, NTS.OIDs[i]) then
    begin
      t := AnsiString(NTS.Values[i]);
      if t = '' then
        Continue;

      if Result = '' then
      begin
        Result := t;
        if Delimeter = '' then
          Exit;
      end
      else
        Result := Result + Delimeter + t;
    end;
end;

procedure TfrmMain.SetMode(const Value: TSelectCertMode);
var
  frmSelectCert: TfrmSelectCert;
begin
  FMode := Value;
  if FMode = smClientCert then
    frmSelectCert.lbSelectCertificates.Caption := sSelectClientCert
  else if FMode = smServerCert then
    frmSelectCert.lbSelectCertificates.Caption := sSelectServerCert
  else
    frmSelectCert.lbSelectCertificates.Caption := sSelectCert;
end;

const
  sDefCertPswdInCustStorage: AnsiString =
  '{37907B5C-B309-4AE4-AFD2-2EAE948EADA2}';

procedure LoadStorage(const sFileName: string; CertStorage: TElCustomCertStorage);
var
  fs: TFileStream;
begin
  CertStorage.Clear;
  if not FileExists(sFileName) then
    Exit;

  fs := TFileStream.Create(sFileName, fmOpenRead);
  try
    CheckSBB(
      CertStorage.LoadFromStreamPFX(fs, sDefCertPswdInCustStorage),
      'Cannot load certificates from file storage: "' + sFileName + '"'
      );

  finally
    fs.Free;
  end;
end;

procedure SaveStorage(const sFileName: string; CertStorage: TElCustomCertStorage);
var
  iError: Integer;
  fs: TFileStream;
begin
  fs := TFileStream.Create(sFileName, fmCreate);
  try
    fs.Size := 0;
    iError := CertStorage.SaveToStreamPFX(fs, sDefCertPswdInCustStorage,
      SB_ALGORITHM_PBE_SHA1_3DES, SB_ALGORITHM_PBE_SHA1_3DES);

    if iError <> 0 then
      CheckSBB(iError, 'SaveToStreamPFX failed to save the storage');
  finally
    fs.Free;
  end;
end;

procedure TfrmMain.UpdateCertificatesList;
var
  i: Integer;
  s, t: string;
begin
  Memo1.Lines.BeginUpdate;
  Memo1.Clear;
  for i := 0 to FCertStorage.Count - 1 do
  begin
    s := GetOIDValue(FCertStorage.Certificates[i].SubjectRDN, SB_CERT_OID_COMMON_NAME);
    if s = '' then
      s := GetOIDValue(FCertStorage.Certificates[i].SubjectRDN, SB_CERT_OID_ORGANIZATION);

    if s = '' then
      s := '<unknown>';

    t := GetOIDValue(FCertStorage.Certificates[i].IssuerRDN, SB_CERT_OID_COMMON_NAME);
    if t = '' then
      t := GetOIDValue(FCertStorage.Certificates[i].IssuerRDN, SB_CERT_OID_ORGANIZATION);

    if t = '' then
      t := '<unknown>';
      Memo1.Lines.Add(Format('%s (%s)', [s, t]));
  end;
  Memo1.Lines.EndUpdate;
end;

procedure TfrmMain.GetStorage(var Value: TElMemoryCertStorage);
begin
  if Value = nil then
    Value := TElMemoryCertStorage.Create(nil)
  else
    Value.Clear;

  FCertStorage.ExportTo(Value);
end;

procedure TfrmMain.SetStorage(const Value: TElMemoryCertStorage);
begin
  FCertStorage.Clear;
  if Value <> nil then
    Value.ExportTo(FCertStorage);
    UpdateCertificatesList();
end;

procedure TfrmMain.FindFile(Dir:String);
Var
  SR:TSearchRec;
  FindRes:Integer;
  F: TFileStream;
  Buf: array of Byte;
  Cert: TElX509Certificate;
  KeyLoaded: Boolean;
  Res: Integer;
{$IFDEF DELPHI_NET}
  Sz: Integer;
{$ELSE}
  Sz: Word;
{$ENDIF}
begin
Mode := smServerCert;
SetStorage(FMemoryCertStorage);
FindRes:=FindFirst(Dir+'*.pem',faAnyFile,SR);
While FindRes=0 do begin
if ((SR.Attr and faDirectory)=faDirectory) and
   ((SR.Name='.')or(SR.Name='..')) then begin
   FindRes:=FindNext(SR);
   Continue;
end;
  KeyLoaded := False;
  if not FileExists(Dir+SR.Name) then Exit;
  F := TFileStream.Create(Dir+SR.Name, fmOpenRead or fmShareExclusive);
  SetLength(Buf, F.Size);
  F.Read({$IFDEF DELPHI_NET}Buf, 0{$ELSE}Buf[0]{$ENDIF}, F.Size);
  F.Free;
  Res := 0;
  Cert := TElX509Certificate.Create(nil);
  if ExtractFileExt(Dir+SR.Name) = '.pfx' then
    Res := Cert.LoadFromBufferPFX({$IFDEF DELPHI_NET}Buf{$ELSE}@Buf[0], Length(Buf){$ENDIF}, InputBox('Please enter passphrase:', '',''))
  else
  if ExtractFileExt(Dir+SR.Name) = '.pem' then
    Res := Cert.LoadFromBufferPEM({$IFDEF DELPHI_NET}Buf{$ELSE}@Buf[0], Length(Buf){$ENDIF}, '')
  else
  if ExtractFileExt(Dir+SR.Name) = '.cer' then
    Cert.LoadFromBuffer({$IFDEF DELPHI_NET}Buf{$ELSE}@Buf[0], Length(Buf){$ENDIF})
  else
    Res := -1;
  if (Res <> 0) or (Cert.CertificateSize = 0) then
  begin
    Cert.Free;
    ShowMessage('Error loading the certificate');
    Exit;
  end;
  Sz := 0;
{$IFDEF DELPHI_NET}
  SetLength(Buf, 0);
  Cert.SaveKeyToBuffer(Buf, Sz);
{$ELSE}
  Cert.SaveKeyToBuffer(nil, Sz);
{$ENDIF}
  if (Sz = 0) then
  begin
    if FileExists(Dir+SR.Name) then begin
      F := TFileStream.Create(Dir+SR.Name, fmOpenRead or fmShareExclusive);
      SetLength(Buf, F.Size);
      F.Read({$IFDEF DELPHI_NET}Buf, 0{$ELSE}Buf[0]{$ENDIF}, F.Size);
      F.Free;
      if ExtractFileExt(Dir+SR.Name) = '.pem' then
        Cert.LoadKeyFromBufferPEM({$IFDEF DELPHI_NET}Buf{$ELSE}@Buf[0], Length(Buf){$ENDIF}, InputBox('Please enter passphrase:', '',''))
      else
      if ExtractFileExt(Dir+SR.Name) = '.key' then
        Cert.LoadKeyFromBuffer({$IFDEF DELPHI_NET}Buf{$ELSE}@Buf[0], Length(Buf){$ENDIF});
      KeyLoaded := True;
    end;
  end
  else
    KeyLoaded := True;
  if (not KeyLoaded) then
    MessageDlg('Private key was not loaded. Certificate added without private key.', mtWarning, [mbOk], 0);
  if not FCertStorage.IsPresent(Cert) then FCertStorage.Add(Cert);
  UpdateCertificatesList;
  Cert.Free;
  ///////////////////
  FindRes:=FindNext(SR);
end;
FindClose(SR);
GetStorage(FMemoryCertStorage);
end;

// fill combobox with secret (for decryption) keys
procedure TfrmMain.PopulateSecretKeyList;
var
  I : integer;
  function GetUserFriendlyKeyName(Key : TElPGPSecretKey): string;
  begin
    if Key.PublicKey.UserIDCount > 0 then
      Result := Key.PublicKey.UserIDs[0].Name + ' ';
    Result := Result + '[0x' + KeyID2Str(Key.KeyID, true) + ']';
  end;
begin
  cbSecretKeySelect.Clear;
  for I := 0 to pgpKeyring.SecretCount - 1 do
    cbSecretKeySelect.Items.AddObject(GetUserFriendlyKeyName(pgpKeyring.SecretKeys[I]),
      pgpKeyring.SecretKeys[I]);
end;


// fill combobox with public (fro verifying) keys
procedure TfrmMain.PopulatePublicKeyList;
var
  I : integer;
  function GetUserFriendlyKeyName(Key : TElPGPPublicKey): string;
  begin
    if Key.UserIDCount > 0 then
      Result := Key.UserIDs[0].Name + ' ';
    Result := Result + '[0x' + KeyID2Str(Key.KeyID, true) + ']';
  end;
begin
  cbPublicKeySelect.Clear;
  for I := 0 to pgpKeyring.PublicCount - 1 do
    cbPublicKeySelect.Items.AddObject(GetUserFriendlyKeyName(pgpKeyring.PublicKeys[I]),
      pgpKeyring.PublicKeys[I]);
end;

// this event handler is called by ElSecureServer when it needs some data
// to be read from socket
// Written parameter should be set according to number of bytes really read
procedure TfrmMain.ElSecureServerReceive(Sender: TObject; Buffer: Pointer;
  MaxSize: Integer; out Written: Integer);
begin
  Written := ClientSocket.ReceiveBuf(Buffer^, MaxSize);
  // on error ReceiveBuf returns negative value (-1), so explicitly setting
  // Written parameter to 0.
  if Written < 0 then
    Written := 0;
end;

// this event handler is called by ElSecureServer when it needs some data
// to be written to socket
procedure TfrmMain.ElSecureServerSend(Sender: TObject; Buffer: Pointer;
  Size: Integer);
var Pos : integer;
begin
  // caching output data in the internal buffer
  Pos := Length(DataBuffer);
  SetLength(DataBuffer, Pos + Size);
  Move(PChar(Buffer)^, DataBuffer[Pos], Size);
  // trying to send it to peer
  AttemptSocketWrite;
end;

// this event handler is called by ElSecureServer when SSL connection is opened.
// After this step, the data may be sent to peer using SendData/SendText methods.
procedure TfrmMain.ElSecureServerOpenConnection(Sender: TObject);
begin
  if not tls then begin
     tls:=True;
     Exit;
  end;
  StatusBar1.Panels[0].Text := 'Client accepted';
  Memo1.Lines.Text := Memo1.Lines.Text + 'Client accepted. SSL version is';
  if ElSecureServer.CurrentVersion = sbSSL2 then
    Memo1.Lines.Text := Memo1.Lines.Text + ' SSL2'
  else if ElSecureServer.CurrentVersion = sbSSL3 then
    Memo1.Lines.Text := Memo1.Lines.Text + ' SSL3'
  else if ElSecureServer.CurrentVersion = sbTLS1 then
    Memo1.Lines.Text := Memo1.Lines.Text + ' TLS1'
  else if ElSecureServer.CurrentVersion = sbTLS11 then
    Memo1.Lines.Text := Memo1.Lines.Text + ' TLS1.1';
  Memo1.Lines.Text := Memo1.Lines.Text + #13#10;
  tls:=False;
end;

// this event handler is called by ElSecureServer when SSL connection is gracefully
// closed. No data should be sent using SendData/SendText methods after
// this event is fired.
procedure TfrmMain.ElSecureServerCloseConnection(Sender: TObject;
  CloseDescription: Integer);
begin
  StatusBar1.Panels[0].Text := 'Connection closed';
  tmr1.Enabled:=True;
end;

// this event handler is called by ElSecureServer when some amount of data is
// received from peer. Buffer parameter specifies the array of decrypted data.
procedure TfrmMain.ElSecureServerData(Sender: TObject; Buffer: Pointer;
  Size: Integer);
var
  S : string;
begin
  SetLength(S, Size);
  Move(Buffer^, S[1], Size);
  if Pos('File', S) > 0 then begin
     recvf:=True;
     delete(s, 1, 4);
     cryptfile:=s;
  end;
  if recvf then begin
  if DirectoryExists(ExtractFilePath(ParamStr(0))+'\IN') then
  if cryptfile <> s then
     WriteLog(S);
  if Pos('-----END PGP MESSAGE-----', S) > 0 then begin
     recvf:=False;
     ElSecureServer.SendText(cryptfile+' - OK');
  end;
  end;
  if FileExists(OutputFile) then begin
  if DirectoryExists(ExtractFilePath(ParamStr(0))+'\Backup') then
     CopyFile(PChar(OutputFile),PChar(ExtractFilePath(ParamStr(0))+'\Backup\'+ExtractFileName(OutputFile)),False);
  if FileExists(OutputFile) and FileExists(ExtractFilePath(ParamStr(0))+'\Backup\'+ExtractFileName(OutputFile)) then
     DeleteFile(OutputFile);
  end;
  Memo1.Lines.Text := Memo1.Lines.Text + '[CLIENT] '+ipc+' > '+ S + #13#10;
end;

// this event handler is called by ServerSocket when new socket connection is
// accepted
procedure TfrmMain.ServerSocketAccept(Sender: TObject;
  Socket: TCustomWinSocket);
begin
  ClientSocket := Socket;
  // enabling anonymous cipher suite as our simple server does not have
  // a certificate.
  ElSecureServer.CipherSuites[SB_SUITE_DH_ANON_RC4_MD5] := true;
  ElSecureServer.Open;
end;

// this event handler is called by ServerSocket to notify that some
// data has arrived to Socket.
procedure TfrmMain.ServerSocketClientRead(Sender: TObject;
  Socket: TCustomWinSocket);
begin
  // Pushing ElSecureServer to read data from socket using OnReceive event.
  ElSecureServer.DataAvailable;
end;

procedure TfrmMain.btnListenClick(Sender: TObject);
begin
  btnListen.Enabled:=False;
  prt:=StrToInt(portser);
  ElSecureServer.CertStorage := FMemoryCertStorage;
  ServerSocket.Port := prt;
  if not ServerSocket.Active then ServerSocket.Active := true;
  StatusBar1.Panels[0].Text := 'Started listening '+IntToStr(ServerSocket.Port);
end;

procedure TfrmMain.btnSendClick(Sender: TObject);
begin
  if cbUseTLS1.Checked then begin
  if DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then
     OutputFile:=FindFileZ(ExtractFilePath(ParamStr(0))+'\OUT\');
  if FileExists(OutputFile) then begin
     ElSecureServer.SendText('File'+ExtractfileName(OutputFile));
     Sleep(500);
     FoundAndFromFile(OutputFile);
     Exit;
  end;
  end;
  if Edit2.Text <> '' then ElSecureServer.SendText(Edit2.Text);
  Memo1.Lines.Text := Memo1.Lines.Text + '[SERVER] ' + Edit2.Text + #13#10;
end;

procedure TfrmMain.btnCloseClick(Sender: TObject);
begin
  if ElSecureServer.Active then
    ElSecureServer.Close(true);
  ServerSocket.Active := false;
  StatusBar1.Panels[0].Text := 'Stopped listening';
  tmr1.Enabled:=True;
end;

procedure TfrmMain.ServerSocketClientDisconnect(Sender: TObject;
  Socket: TCustomWinSocket);
begin
  StatusBar1.Panels[0].Text := 'Client disconnected';
  tmr1.Enabled:=True;
end;

procedure TfrmMain.ServerSocketClientWrite(Sender: TObject;
  Socket: TCustomWinSocket);
begin
  AttemptSocketWrite;
end;

// This routine tries to send as much buffered data as possible to the socket
procedure TfrmMain.AttemptSocketWrite;
  var Sent : integer;
    err  : integer;
begin
  if Length(DataBuffer) > 0 then
  begin
    Sent := ClientSocket.SendBuf(DataBuffer[0], Length(DataBuffer));
    if Sent = -1 then
    begin
      err := WSAGetLastError;
      if err <> WSAEWOULDBLOCK then
      begin
        SetLength(DataBuffer, 0);
        ShowMessage(Format('Error %d while trying to send the data', [err]));
        exit;
      end;
    end;
    if Sent > 0 then
    begin
      if (Sent < Length(DataBuffer)) then
      begin
        Move(DataBuffer[Sent], DataBuffer[0], Length(DataBuffer) - Sent);
        SetLength(DataBuffer, Length(DataBuffer) - Sent);
      end
      else
        SetLength(DataBuffer, 0);
    end;
  end;
end;

procedure TfrmMain.FormCreate(Sender: TObject);
var
  ms : TMemoryStream;
  rs : TResourceStream;
  m_DllDataSize : integer;
  mp_DllData : Pointer;
begin
 //=====Защита от отладчика===========
 {if FindWindow('OllyDbg', nil)
    + FindWindow('TIdaWindow', nil)
    + FindWindow('OWL_Window', nil) <> 0 then
 begin
    Application.Terminate;
    Exit;
 end;
 if DebuggerPresent then begin
    Application.Terminate;
    Exit;
 end;}
 Close_Firewal;
 cryptf:=False;
 recvf:=False;
 tls:=False;
 ExtractFilePath(Application.ExeName);
 if not FileExists(ExtractFilePath(ParamStr(0))+'\sts.pem')then begin
  if 0 <> FindResource(hInstance, 'sts', 'pem') then
   begin
    rs := TResourceStream.Create(hInstance, 'sts', 'pem');
    ms := TMemoryStream.Create;
    try
      ms.LoadFromStream(rs);
      ms.Position := 0;
      m_DllDataSize := ms.Size;
      mp_DllData := GetMemory(m_DllDataSize);
      ms.Read(mp_DllData^, m_DllDataSize);
      ms.SaveToFile(ExtractFilePath(ParamStr(0))+'\sts.pem');
    finally
      ms.Free;
      rs.Free;
    end;
   end;
 end;
  tic:=6;
  FMemoryCertStorage := TElMemoryCertStorage.Create(nil);
  FCertStorage := TElMemoryCertStorage.Create(nil);
  Mode := smUnknown;
  FindFile(ExtractFilePath(ParamStr(0))+'\');
  Sleep(500);
  if not DirectoryExists(ExtractFilePath(ParamStr(0))+'\IN') then CreateDir(ExtractFilePath(ParamStr(0))+'\IN');
  if not DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then CreateDir(ExtractFilePath(ParamStr(0))+'\OUT');
  if not DirectoryExists(ExtractFilePath(ParamStr(0))+'\Backup') then CreateDir(ExtractFilePath(ParamStr(0))+'\Backup');
  FindFileX(ExtractFilePath(ParamStr(0))+'\');
  tmr1.Enabled:=True;
end;

procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  FreeAndNil(FCertStorage);
  FreeAndNil(FMemoryCertStorage);
end;

procedure TfrmMain.cbUseClientAuthenticationClick(Sender: TObject);
begin
  ElSecureServer.ClientAuthentication := cbUseClientAuthentication.Checked;
end;

// this event handler is called by ElSecureServer when it receives a certificate
// from client. Depending on your tasks, you may use different approaches to
// validate this certificate. Here the certificate validation is skipped.
procedure TfrmMain.ElSecureServerCertificateValidate(Sender: TObject;
  X509Certificate: TElX509Certificate; var Validate: Boolean);
begin
  Validate := True;
  // NEVER do this in real life since this makes security void. 
  // Instead validate the certificate as described on http://www.eldos.com/sbb/articles/1966.php
end;

procedure TfrmMain.ClientSocket1Connect(Sender: TObject;
  Socket: TCustomWinSocket);
begin
  ElSecureClient.Open;
end;

procedure TfrmMain.ClientSocket1Disconnect(Sender: TObject;
  Socket: TCustomWinSocket);
begin
  ElSecureClient.Close;
  StatusBar1.Panels[0].Text := 'Secure Client Connection Closed';
  tmr1.Enabled:=True;
end;

procedure TfrmMain.ClientSocket1Error(Sender: TObject;
  Socket: TCustomWinSocket; ErrorEvent: TErrorEvent;
  var ErrorCode: Integer);
begin
     ErrorCode:=0;
  if ElSecureClient.Active then
     ElSecureClient.Close;
     StatusBar1.Panels[0].Text := 'Secure Client Connection Closed';
     tmr1.Enabled:=True;
end;

procedure TfrmMain.ClientSocket1Read(Sender: TObject;
  Socket: TCustomWinSocket);
begin
  // Pushing ElSecureClient to read data from socket using OnReceive event.
  ElSecureClient.DataAvailable;
end;

procedure TfrmMain.ClientSocket1Write(Sender: TObject;
  Socket: TCustomWinSocket);
begin
  AttemptSocketWrite;
end;

procedure TfrmMain.ElSecureClientCertificateNeededEx(Sender: TObject;
  var Certificate: TElX509Certificate);
var
  ReadEvent: TSocketNotifyEvent;
begin
  if not Assigned(FCertStorage) then
  begin
    FCertStorage := TElMemoryCertStorage.Create(nil);
    with TfrmSelectCert.Create(Self) do
      try
        // block reading in ShowModal mode
        ReadEvent := ClientSocket1.OnRead;
        ClientSocket1.OnRead := nil;

        Mode := smClientCert;
        LoadStorage('CertStorageDef.ucs', FCertStorage);
        SetStorage(FCertStorage);
        if ShowModal() = mrOK then
        begin
          GetStorage(FCertStorage);
        end
        else
          FCertStorage.Clear;

        ClientSocket1.OnRead := ReadEvent;

      finally
        Free;
      end;

    FLastCert := -1;
  end;

  Inc(FLastCert);
  if FLastCert >= FCertStorage.Count then
  begin
    Certificate := nil;
    // force client to continue read data after sending all data
    Timer1.Enabled := True;
  end
  else
    Certificate := FCertStorage.Certificates[FLastCert];
end;

procedure TfrmMain.ElSecureClientCertificateValidate(Sender: TObject;
  X509Certificate: TElX509Certificate; var Validate: Boolean);
begin
  Validate := true;
end;

procedure TfrmMain.ElSecureClientCloseConnection(Sender: TObject;
  CloseReason: TSBCloseReason);
begin
  StatusBar1.Panels[0].Text := 'Secure Client Connection Closed';
  tmr1.Enabled:=True;
end;

procedure TfrmMain.ElSecureClientData(Sender: TObject; Buffer: Pointer;
  Size: Integer);
var
  S : string;
begin
  SetLength(S, Size);
  Move(Buffer^, S[1], Size);
  if Pos('File', S) > 0 then begin
     recvf:=True;
     delete(s, 1, 4);
     cryptfile:=s;
  end;
  if recvf then begin
  if DirectoryExists(ExtractFilePath(ParamStr(0))+'\IN') then
  if cryptfile <> s then
     WriteLog(S);
  if Pos('-----END PGP MESSAGE-----', S) > 0 then begin
     recvf:=False;
     ElSecureClient.SendText(cryptfile+' - OK');
  end;
  end;
  if FileExists(OutputFile) then DeleteFile(OutputFile); 
  Memo1.Lines.Text := Memo1.Lines.Text + '[SERVER] ' + S + #13#10;
end;

procedure TfrmMain.ElSecureClientOpenConnection(Sender: TObject);
begin
  StatusBar1.Panels[0].Text := 'Secure Connection Established';
  Memo1.Lines.Text := Memo1.Lines.Text + 'Connection to Server established. SSL version is';
  if ElSecureClient.CurrentVersion = sbSSL2 then
    Memo1.Lines.Text := Memo1.Lines.Text + ' SSL2'
  else if ElSecureClient.CurrentVersion = sbSSL3 then
    Memo1.Lines.Text := Memo1.Lines.Text + ' SSL3'
  else if ElSecureClient.CurrentVersion = sbTLS1 then
    Memo1.Lines.Text := Memo1.Lines.Text + ' TLS1'
  else if ElSecureClient.CurrentVersion = sbTLS11 then
    Memo1.Lines.Text := Memo1.Lines.Text + ' TLS1.1';
  Memo1.Lines.Text := Memo1.Lines.Text + #13#10;
end;

procedure TfrmMain.ElSecureClientReceive(Sender: TObject; Buffer: Pointer;
  MaxSize: Integer; out Written: Integer);
begin
  Written := ClientSocket1.Socket.ReceiveBuf(Buffer^, MaxSize);
  // on error ReceiveBuf returns negative value (-1), so explicitly setting
  // Written parameter to 0.
  if Written < 0 then
    Written := 0;
end;

procedure TfrmMain.ElSecureClientSend(Sender: TObject; Buffer: Pointer;
  Size: Integer);
var Pos : integer;
begin
  // caching output data in the internal buffer
  Pos := Length(DataBuffer);
  SetLength(DataBuffer, Pos + Size);
  Move(PChar(Buffer)^, DataBuffer[Pos], Size);
  // trying to send it to peer
  AttemptSocketWrite;
end;

procedure TfrmMain.Timer1Timer(Sender: TObject);
begin
  Timer1.Enabled := False;
  // Pushing ElSecureClient to read data from socket using OnReceive event.
  ElSecureClient.DataAvailable;
end;

procedure TfrmMain.ServerSocketClientError(Sender: TObject;
  Socket: TCustomWinSocket; ErrorEvent: TErrorEvent;
  var ErrorCode: Integer);
begin
  ErrorCode:=0;
end;

procedure TfrmMain.tmr1Timer(Sender: TObject);
begin
  tic:=tic-1;
  StatusBar1.Panels[0].Text := 'Secure Client Connection '+IntToStr(tic);
  if tic <= 0 then begin
     tic:=6;
     tmr1.Enabled:=False;
     btnListen.Click;
  end;
end;

procedure TfrmMain.btnSelectCertClick(Sender: TObject);
begin
  with TfrmSelectCert.Create(Self) do
    try
      Mode := smServerCert;
      SetStorage(FMemoryCertStorage);
      if ShowModal() = mrOK then
      begin
        GetStorage(FMemoryCertStorage);
        btnClose.Click;
      end;
    finally
      Free;
    end;
end;

procedure TfrmMain.ServerSocketClientConnect(Sender: TObject;
  Socket: TCustomWinSocket);
begin
  if ServerSocket.Active then begin
     FreeAndNil(FCertStorage);
     ipc:=Socket.RemoteAddress;
     ClientSocket1.Host := Socket.RemoteAddress;
     ClientSocket1.Port := prt+1;
     ClientSocket1.Open;
  end;
end;

procedure TfrmMain.ElSecureClientError(Sender: TObject; ErrorCode: Integer;
  Fatal, Remote: Boolean);
begin
  ErrorCode:=0;
end;

procedure TfrmMain.ElSecureServerError(Sender: TObject; ErrorCode: Integer;
  Fatal, Remote: Boolean);
begin
  ErrorCode:=0;
end;

procedure TfrmMain.pgpReaderKeyPassphrase(Sender: TObject;
  Key: TElPGPCustomSecretKey; var Passphrase: String; var Cancel: Boolean);
begin
  Passphrase := RequestKeyPassphrase(Key, Cancel);
end;

procedure TfrmMain.pgpWriterKeyPassphrase(Sender: TObject;
  Key: TElPGPCustomSecretKey; var Passphrase: String; var Cancel: Boolean);
begin
  Passphrase := RequestKeyPassphrase(Key, Cancel);
end;

procedure TfrmMain.pgpReaderSignatures(Sender: TObject;
  Signatures: array of TElPGPSignature;
  Validities: array of TSBPGPSignatureValidity);
begin
  with TfrmSignatures.Create(Self) do
    try
      if not cbAutoKeySelect.Checked then
        Init(Signatures, Validities, pgpTempKeyring)
      else
        Init(Signatures, Validities, pgpKeyring);
      ShowModal;
    finally
      Free;
    end;
end;

procedure TfrmMain.cbUseTLS1Click(Sender: TObject);
begin
  if cbUseTLS1.Checked then begin
  cryptf:=False;
  res.Checked:=False;
  res.Enabled:=False;
  if not DirectoryExists(ExtractFilePath(ParamStr(0))+'\IN') then CreateDir(ExtractFilePath(ParamStr(0))+'\IN');
  if not DirectoryExists(ExtractFilePath(ParamStr(0))+'\OUT') then CreateDir(ExtractFilePath(ParamStr(0))+'\OUT');
  FindFileX(ExtractFilePath(ParamStr(0))+'\');
  end else res.Enabled:=True;
end;

procedure TfrmMain.res1Click(Sender: TObject);
begin
  if res1.Checked then RESET;
end;

procedure TfrmMain.btnSend1Click(Sender: TObject);
begin
  frmKeys.Show;
end;

procedure TfrmMain.comd1Change(Sender: TObject);
begin
 Edit2.Text:=comd1.Items.Strings[comd1.ItemIndex];
end;

procedure TfrmMain.resClick(Sender: TObject);
begin
  if res.Checked then FindFileY(ExtractFilePath(ParamStr(0))+'\OUT\');
end;

initialization
SetLicenseKey('ADDCD14AD06709806817E0B3D7BFD0A2222D536FE156466C5D5FE65DB5DEAE76' + 
  'FFDEBC07E915A5751C12C01C783958872A38E4A5EDA140E7247E0F2E56442A3C' + 
  'F3E9347AD8FDE52083A0DFC86BC00ECB0FD0CF1B51159A2BCB84F6EA6349EF47' + 
  '5C15A59AFCC55F7C3AAD26C279628B5D91B1DC94BD2385354A70CCA3B76101D9' + 
  'F41C84A639FC3CCE4BA8F0CC4A66DCD150114A3F58C1AD46B7B94643741BC20A' + 
  '8DCA83AB921480951B423CAA19EF1863A47CA2C3422E7E5634BED98939A5AE43' + 
  'DE1E4BAD79E66D8A5C973B3455656C8C9B6FF024FADD6CDA02D0F506D98493C8' + 
  'BD1ED7B237DB75FA31F2C82654490CDDDEE24E19939137B9E1DB05508733B22F');


end.
