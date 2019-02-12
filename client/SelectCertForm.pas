unit SelectCertForm;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls,
  SBX509, SBRDN, SBUtils, SBConstants, SBCustomCertStorage, ExtCtrls;

type
  TSelectCertMode = (smUnknown, smClientCert, smServerCert);

  TfrmSelectCert = class(TForm)
    lbxCertificates: TListBox;
    lbSelectCertificates: TLabel;
    btnAddCertificate: TButton;
    btnRemoveCertificate: TButton;
    OpenDlg: TOpenDialog;
    btnCancel: TButton;
    btnOK: TButton;
    btnLoadStorage: TButton;
    btnSaveStorage: TButton;
    Bevel1: TBevel;
    SaveDlg: TSaveDialog;
    Bevel2: TBevel;
    procedure btnAddCertificateClick(Sender: TObject);
    procedure btnRemoveCertificateClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnLoadStorageClick(Sender: TObject);
    procedure btnSaveStorageClick(Sender: TObject);
  private
    FCertStorage: TElMemoryCertStorage;
    FMode: TSelectCertMode;

    procedure SetMode(const Value: TSelectCertMode);
  protected
    procedure UpdateCertificatesList;
  public
    procedure GetStorage(var Value: TElMemoryCertStorage);
    procedure SetStorage(const Value: TElMemoryCertStorage);

    property Mode: TSelectCertMode read FMode write SetMode;
  end;

function GetOIDValue(NTS: TElRelativeDistinguishedName; const S: BufferType; const Delimeter: AnsiString = ' / '): AnsiString;

procedure LoadStorage(const sFileName: string; CertStorage: TElCustomCertStorage);
procedure SaveStorage(const sFileName: string; CertStorage: TElCustomCertStorage);

resourcestring
  sSelectClientCert = 'Please, choose client-side certificate or certificate chain.'#13#10'The server has client authentication enabled.';
  sSelectServerCert = 'Please, choose server certificates.';
  sSelectCert = 'Please, choose certificates.';

implementation

{$R *.DFM}

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

procedure TfrmSelectCert.btnAddCertificateClick(Sender: TObject);
var
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
  KeyLoaded := False;
  OpenDlg.FileName := '';
  OpenDlg.Title := 'Select certificate file';
  OpenDlg.Filter := 'PEM-encoded certificate (*.pem)|*.pem|DER-encoded certificate (*.cer)|*.cer|PFX-encoded certificate (*.pfx)|*.pfx';
  if not OpenDlg.Execute then
    Exit;

  F := TFileStream.Create(OpenDlg.Filename, fmOpenRead or fmShareExclusive);
  SetLength(Buf, F.Size);
  F.Read({$IFDEF DELPHI_NET}Buf, 0{$ELSE}Buf[0]{$ENDIF}, F.Size);
  F.Free;

  Res := 0;
  Cert := TElX509Certificate.Create(nil);
  if OpenDlg.FilterIndex = 3 then
    Res := Cert.LoadFromBufferPFX({$IFDEF DELPHI_NET}Buf{$ELSE}@Buf[0], Length(Buf){$ENDIF}, InputBox('Please enter passphrase:', '',''))
  else
  if OpenDlg.FilterIndex = 1 then
    Res := Cert.LoadFromBufferPEM({$IFDEF DELPHI_NET}Buf{$ELSE}@Buf[0], Length(Buf){$ENDIF}, '')
  else
  if OpenDlg.FilterIndex = 2 then
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
    OpenDlg.Title := 'Select the corresponding private key file';
    OpenDlg.Filter := 'PEM-encoded key (*.pem)|*.PEM|DER-encoded key (*.key)|*.key';
    if OpenDlg.Execute then
    begin
      F := TFileStream.Create(OpenDlg.Filename, fmOpenRead or fmShareExclusive);
      SetLength(Buf, F.Size);
      F.Read({$IFDEF DELPHI_NET}Buf, 0{$ELSE}Buf[0]{$ENDIF}, F.Size);
      F.Free;

      if OpenDlg.FilterIndex = 1 then
        Cert.LoadKeyFromBufferPEM({$IFDEF DELPHI_NET}Buf{$ELSE}@Buf[0], Length(Buf){$ENDIF}, InputBox('Please enter passphrase:', '',''))
      else
        Cert.LoadKeyFromBuffer({$IFDEF DELPHI_NET}Buf{$ELSE}@Buf[0], Length(Buf){$ENDIF});

      KeyLoaded := True;
    end;
  end
  else
    KeyLoaded := True;

  if (not KeyLoaded) then
    MessageDlg('Private key was not loaded. Certificate added without private key.', mtWarning, [mbOk], 0);

  if not FCertStorage.IsPresent(Cert) then
    FCertStorage.Add(Cert);
    
  UpdateCertificatesList;

  Cert.Free;
end;

procedure TfrmSelectCert.btnRemoveCertificateClick(Sender: TObject);
begin
  if lbxCertificates.ItemIndex >= 0 then
  begin
    FCertStorage.Remove(lbxCertificates.ItemIndex);
    UpdateCertificatesList;
  end;
end;

procedure TfrmSelectCert.SetMode(const Value: TSelectCertMode);
begin
  FMode := Value;
  if FMode = smClientCert then
    lbSelectCertificates.Caption := sSelectClientCert
  else if FMode = smServerCert then
    lbSelectCertificates.Caption := sSelectServerCert
  else
    lbSelectCertificates.Caption := sSelectCert;
end;

procedure TfrmSelectCert.UpdateCertificatesList;
var
  i: Integer;
  s, t: string;
begin
  lbxCertificates.Items.BeginUpdate;
  lbxCertificates.Clear;
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

    lbxCertificates.Items.Add(Format('%s (%s)', [s, t]));
  end;

  lbxCertificates.Items.EndUpdate;
end;

procedure TfrmSelectCert.FormCreate(Sender: TObject);
begin
  FCertStorage := TElMemoryCertStorage.Create(nil);
  Mode := smUnknown;
end;

procedure TfrmSelectCert.FormDestroy(Sender: TObject);
begin
  FreeAndNil(FCertStorage);
end;

procedure TfrmSelectCert.GetStorage(var Value: TElMemoryCertStorage);
begin
  if Value = nil then
    Value := TElMemoryCertStorage.Create(nil)
  else
    Value.Clear;

  FCertStorage.ExportTo(Value);
end;

procedure TfrmSelectCert.SetStorage(const Value: TElMemoryCertStorage);
begin
  FCertStorage.Clear;
  if Value <> nil then
    Value.ExportTo(FCertStorage);

  UpdateCertificatesList();
end;

procedure TfrmSelectCert.btnLoadStorageClick(Sender: TObject);
begin
  OpenDlg.Filter := 'Users Certificates Storage (*.ucs)|*.ucs|All Files (*.*)|*.*';
  OpenDlg.FilterIndex := 0;
  OpenDlg.Title := 'Load Storage';
  OpenDlg.FileName := '';
  if OpenDlg.Execute then
  begin
    LoadStorage(OpenDlg.FileName, FCertStorage);
    UpdateCertificatesList();
  end;
end;

procedure TfrmSelectCert.btnSaveStorageClick(Sender: TObject);
begin
  SaveDlg.Filter := 'Users Certificates Storage (*.ucs)|*.ucs|All Files (*.*)|*.*';
  SaveDlg.FilterIndex := 0;
  SaveDlg.DefaultExt := '.ucs';
  SaveDlg.Title := 'Save Storage';
  SaveDlg.FileName := '';
  if SaveDlg.Execute then
    SaveStorage(SaveDlg.FileName, FCertStorage);
end;

end.
