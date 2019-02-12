unit PassphraseRequestForm;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls;

type
  TfrmPassphraseRequest = class(TForm)
    lbPrompt: TLabel;
    edPassphrase: TEdit;
    btnOK: TButton;
    btnCancel: TButton;
    lbKeyID: TLabel;
  private
    { Private declarations }
  public
    { Public declarations }
  end;

implementation

{$R *.DFM}

end.
