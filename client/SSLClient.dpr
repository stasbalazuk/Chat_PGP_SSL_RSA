{$R UAC.RES}
program SSLClient;

uses
  Forms,
  MainForm in 'MainForm.pas' {frmMain},
  SignaturesForm in 'SignaturesForm.pas' {frmSignatures},
  SelectCertForm in 'SelectCertForm.pas' {frmSelectCert};

{$R *.RES}

begin
  Application.Initialize;
  Application.CreateForm(TfrmMain, frmMain);
  Application.CreateForm(TfrmSignatures, frmSignatures);
  Application.Run;
end.
