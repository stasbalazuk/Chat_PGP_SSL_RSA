object frmSelectCert: TfrmSelectCert
  Left = 489
  Top = 285
  BorderStyle = bsDialog
  Caption = 'Select Certificates'
  ClientHeight = 265
  ClientWidth = 462
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  Position = poOwnerFormCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  DesignSize = (
    462
    265)
  PixelsPerInch = 96
  TextHeight = 13
  object lbSelectCertificates: TLabel
    Left = 8
    Top = 8
    Width = 448
    Height = 33
    Anchors = [akLeft, akTop, akRight]
    AutoSize = False
    Caption = 'Please, choose certificates.'
    WordWrap = True
  end
  object Bevel1: TBevel
    Left = 349
    Top = 108
    Width = 109
    Height = 5
    Anchors = [akTop, akRight]
    Shape = bsBottomLine
  end
  object Bevel2: TBevel
    Left = 4
    Top = 222
    Width = 456
    Height = 5
    Anchors = [akLeft, akRight, akBottom]
    Shape = bsBottomLine
  end
  object lbxCertificates: TListBox
    Left = 8
    Top = 48
    Width = 336
    Height = 169
    Anchors = [akLeft, akTop, akRight, akBottom]
    ImeName = 'Russian'
    ItemHeight = 13
    TabOrder = 0
  end
  object btnAddCertificate: TButton
    Left = 351
    Top = 48
    Width = 105
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'Add certificate'
    TabOrder = 1
    OnClick = btnAddCertificateClick
  end
  object btnRemoveCertificate: TButton
    Left = 351
    Top = 80
    Width = 105
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'Remove certificate'
    TabOrder = 2
    OnClick = btnRemoveCertificateClick
  end
  object btnCancel: TButton
    Left = 383
    Top = 234
    Width = 75
    Height = 25
    Anchors = [akRight, akBottom]
    Cancel = True
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 3
  end
  object btnOK: TButton
    Left = 303
    Top = 234
    Width = 75
    Height = 25
    Anchors = [akRight, akBottom]
    Caption = 'OK'
    ModalResult = 1
    TabOrder = 4
  end
  object btnLoadStorage: TButton
    Left = 351
    Top = 120
    Width = 105
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'Load Storage'
    TabOrder = 5
    OnClick = btnLoadStorageClick
  end
  object btnSaveStorage: TButton
    Left = 351
    Top = 152
    Width = 105
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'Save Storage'
    TabOrder = 6
    OnClick = btnSaveStorageClick
  end
  object OpenDlg: TOpenDialog
    Left = 80
    Top = 112
  end
  object SaveDlg: TSaveDialog
    Left = 112
    Top = 112
  end
end
