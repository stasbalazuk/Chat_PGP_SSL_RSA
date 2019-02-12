{$R UAC.RES}
program SSLServer;

uses
  Forms,
  MainForm in 'MainForm.pas' {frmMain},
  SignaturesForm in 'SignaturesForm.pas' {frmSignatures},  
  genkey in 'genkey.pas' {frmKeys},
  Keyring in 'Keyring.pas' {frmSelectKeyring},
  Wizard in 'Wizard.pas' {frmWizard},
  Keys in 'Keys.pas' {frmPrivateKeys},
  PassphraseRequestForm in 'PassphraseRequestForm.pas' {frmPassphraseRequest},
  ImportKeyForm in 'ImportKeyForm.pas' {frmImportKey},
  SelectCertForm in 'SelectCertForm.pas' {frmSelectCert};

{$R *.RES}

begin
  Application.Initialize;
  Application.Title := 'PGPKeys RSA SSL Server';
  Application.CreateForm(TfrmMain, frmMain);
  Application.CreateForm(TfrmKeys, frmKeys);
  //Application.CreateForm(TfrmSignatures, frmSignatures);  
  Application.Run;
end.
