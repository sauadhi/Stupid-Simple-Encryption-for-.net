# Stupid-Simple-Encryption-for-.net
Stupid Simple .net encryption class

This project is derived from earlier personal code and is now shared under Apache 2.0 for broad reuse.




Example of wiring this in a form (pseudo-simplified; put in your Form code-behind):

```csharp

var service = new LoginService(
new ApiOptions { BaseUri = new Uri("https://api.example.com/"), RSAPublicKeyXml = "..." },
new HttpClientApi(),
new DefaultCryptoFacade(),
new SecureRandomProvider());

var hwid = new BasicHardwareIdProvider();
var result = await service.LoginAsync(txtUser.Text, txtPass.Text, hwid, this._cts.Token);
if (result.Success) { /* proceed */ } else { MessageBox.Show(result.Error); }
```
