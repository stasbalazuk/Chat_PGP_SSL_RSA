�
 TFRMMAIN 0a  TPF0TfrmMainfrmMainLeft�Top� BorderIconsbiSystemMenu
biMinimize BorderStylebsSingleCaptionSSL - RSA ClientClientHeightClientWidth�Color	clBtnFaceFont.CharsetDEFAULT_CHARSET
Font.ColorclWindowTextFont.Height�	Font.NameMS Sans Serif
Font.Style 	FormStylefsStayOnTopOldCreateOrderPositionpoScreenCenterOnCreate
FormCreate	OnDestroyFormDestroyPixelsPerInch`
TextHeight 	TGroupBox	GroupBox1Left Top Width�Height� AlignalTopCaptionConnectTabOrder  TLabellblSecretKeyListLeftTop`Width� HeightCaption6   Список ключей для дешифровки:Enabled  TLabellblPublicKeyListLeftTop� WidthHeightCaption(   Ключ для проверки ЭЦП:Enabled  TButton
btnConnectLeftTopWidthIHeightCaption   :;NG8BLTabOrder OnClickbtnConnectClick  TButtonbtnDisconnectLeft`TopWidthIHeightCaption	   K:;NG8BLTabOrderOnClickbtnDisconnectClick  	TCheckBoxcbUseClientAuthenticationLeftTopWidthqHeightCaption   CB5=B8D8:0F8OChecked	EnabledState	cbCheckedTabOrderOnClickcbUseClientAuthenticationClick  	TCheckBoxcbAutoKeySelectLeftTop Width� HeightCaption6   Автоматически выбирать ключиChecked	State	cbCheckedTabOrder  	TComboBoxcbSecretKeySelectLeftToppWidth�HeightStylecsDropDownListEnabled
ItemHeightTabOrder  	TComboBoxcbPublicKeySelectLeftTop� Width�HeightStylecsDropDownListEnabled
ItemHeightTabOrder  	TCheckBox	cbUseTLS1LeftTop0WidthqHeightCaption   Отправить файлTabOrderOnClickcbUseTLS1Click  	TCheckBoxres1LeftTop@Width� HeightCaption'   Перезапуск программыTabOrderOnClick	res1Click  	TCheckBoxresLeftTopPWidth� HeightCaption0   Копировать файлы в папку INTabOrderOnClickresClick   
TStatusBar
StatusBar1Left Top�Width�HeightPanelsTextStartedWidth2    	TGroupBoxgrp1Left Top� Width�HeightAlignalBottomCaption   Лог сообщений:TabOrder TMemoMemo1LeftTopWidth�Height� AlignalClientImeNameRussian
ScrollBarsssBothTabOrder    	TGroupBoxgrp2Left Top� Width�Height9AlignalBottomCaption	   !>>1I5=85TabOrder TEditEdit3LeftTopWidthQHeightFont.CharsetDEFAULT_CHARSET
Font.ColorclWindowTextFont.Height�	Font.NameMS Sans Serif
Font.Style ImeNameRussian
ParentFontTabOrder   TButtonbtnSendLeft^TopWidthKHeightCaption	   B?@028BLDefault	TabOrderOnClickbtnSendClick   TElSecureClientElSecureClientVersionssbSSL2sbSSL3sbTLS1sbTLS11 Options OnSendElSecureClientSend	OnReceiveElSecureClientReceiveOnDataElSecureClientDataOnOpenConnectionElSecureClientOpenConnectionOnCertificateValidate!ElSecureClientCertificateValidateOnErrorElSecureClientError!RenegotiationAttackPreventionModerapmCompatibleOnCloseConnectionElSecureClientCloseConnectionOnCertificateNeededEx!ElSecureClientCertificateNeededExLeft0Top  TClientSocketClientSocket1Active
ClientTypectNonBlockingPort 	OnConnectClientSocket1ConnectOnDisconnectClientSocket1DisconnectOnReadClientSocket1ReadOnWriteClientSocket1WriteOnErrorClientSocket1ErrorLeft0Top8  TTimerTimer1Interval�OnTimerTimer1TimerLeftPTop  TElSecureServerElSecureServerVersionssbSSL2sbSSL3sbTLS1sbTLS11 Options OnSendElSecureServerSend	OnReceiveElSecureServerReceiveOnDataElSecureServerDataOnOpenConnectionElSecureServerOpenConnectionOnCertificateValidate!ElSecureServerCertificateValidateOnErrorElSecureServerErrorEnabled	ClientAuthenticationAbortOnMissingSRPName!RenegotiationAttackPreventionModerapmCompatibleOnCloseConnectionElSecureServerCloseConnectionLeftTop8  TServerSocketServerSocketActivePort 
ServerTypestNonBlockingOnAcceptServerSocketAcceptOnClientDisconnectServerSocketClientDisconnectOnClientReadServerSocketClientReadOnClientWriteServerSocketClientWriteOnClientErrorServerSocketClientErrorLeftTop  TTimertmr1EnabledOnTimer	tmr1TimerLeftPTop8  TElPGPKeyringpgpTempKeyringLeft� Top  TElPGPKeyring
pgpKeyringLeft� Top  TElPGPReader	pgpReaderMemoryConsumptionStrategy	mcsGreedyOnKeyPassphrasepgpReaderKeyPassphraseOnSignaturespgpReaderSignaturesLeftxTop  TElPGPWriter	pgpWriterArmorEncryptionTypeetPublicKeyCompressCompressionAlgorithmCompressionLevel	OnKeyPassphrasepgpWriterKeyPassphraseLeftxTop(   