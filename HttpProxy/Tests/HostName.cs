using System;
using System.Collections.Generic;
using System.Net;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace HttpProxy
{
  [TestClass]
  public class HostName
  {

    #region (DE)INIT

    [TestInitialize]
    public void TestInit()
    {
      var certPath = HelperMethods.Inst.GenerateCertificate(Config.CertificateHost);

      //Proxy muss im Hintergrund gestartet werden!!
      HelperMethods.Inst.StartProxyServers(certPath);
      Console.WriteLine($"Proxy startet. Http:{Config.LocalHttpPort}, Https:{Config.LocalHttpsPort}");
    }


    [TestCleanup]
    public void TestClean()
    {
      HelperMethods.Inst.StopProxyServers();
    }

    #endregion


    #region MEMBERS

    private HttpReverseProxy.ClientErrorHandler httpErrorMsgs = new HttpReverseProxy.ClientErrorHandler();

    #endregion


    [TestMethod]
    public void InvalidHostname()
    {
      var headers = new List<string>() { "Host: spin.ch/", "Connection: keep-alive" };
      var response = HelperMethods.Inst.SendRawGET("http", "127.0.0.1", Config.LocalHttpPort, "/", headers);
      
      Assert.IsTrue(response.Contains(httpErrorMsgs.statusDescription[HttpStatusCode.BadRequest].Code.ToString()));
      Assert.IsTrue(response.Contains(httpErrorMsgs.statusDescription[HttpStatusCode.BadRequest].Title));
      Assert.IsTrue(response.Contains(httpErrorMsgs.statusDescription[HttpStatusCode.BadRequest].Description));
    }


    [TestMethod]
    public void UnknownHostname()
    {
      var headers = new List<string>() { "Host: kawalumpalumpa.com/", "Connection: keep-alive" };
      var response = HelperMethods.Inst.SendRawGET("http", "127.0.0.1", Config.LocalHttpPort, "/", headers);

      Assert.IsTrue(response.Contains(httpErrorMsgs.statusDescription[HttpStatusCode.BadRequest].Code.ToString()));
      Assert.IsTrue(response.Contains(httpErrorMsgs.statusDescription[HttpStatusCode.BadRequest].Title));
      Assert.IsTrue(response.Contains(httpErrorMsgs.statusDescription[HttpStatusCode.BadRequest].Description));
    }


    [TestMethod]
    public void ValidHostname()
    {
      var headers = new List<string>() { "Host: spin.ch", "Connection: keep-alive" };
      var response = HelperMethods.Inst.SendRawGET("http", "127.0.0.1", Config.LocalHttpPort, "/", headers);

      Assert.IsTrue(response.Contains(httpErrorMsgs.statusDescription[HttpStatusCode.OK].Code.ToString()));
      Assert.IsTrue(response.Contains(httpErrorMsgs.statusDescription[HttpStatusCode.OK].Title));
    }
  }
}
