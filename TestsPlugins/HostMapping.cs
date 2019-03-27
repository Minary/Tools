using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using HttpReverseProxy.Plugin.HostMapping;
using HttpReverseProxyLib.DataTypes.Class;
using HttpReverseProxyLib.DataTypes.Enum;
using HttpReverseProxyLib.DataTypes.Interface;
using HttpReverseProxyLib;

namespace TestPlugins
{
  [TestClass]
  public class HostMapping
  {

    #region MEMBERS

    private string pathInputFile;

    #endregion


    [TestInitialize]
    public void TestInit()
    {
      this.pathInputFile = Path.GetTempFileName();
    }


    [TestCleanup]
    public void TestClean()
    {
      if (File.Exists(this.pathInputFile))
      {
        try
        {
          File.Delete(this.pathInputFile);
        }
        catch (Exception ex)
        {
          Console.WriteLine($"TestClearn(EXC): {ex.Message}");
        }
      }
    }


    [TestMethod]
    public void LoadConfig_Wildcard()
    {
      File.AppendAllText(this.pathInputFile, "*oogle.c*||www.altavista.com");
      var conf = new Config();
      conf.ParseConfigurationFile(this.pathInputFile);

      Assert.IsTrue(Config.MappingsHostWildcards.Count == 1);
      Assert.IsTrue(Config.MappingsHostname.Count == 0);
    }


    [TestMethod]
    public void LoadConfig_FixHostname()
    {
      File.AppendAllText(this.pathInputFile, $"google.com||www.altavista.com{Environment.NewLine}www.google.com||www.altavista.com");
      var conf = new Config();
      conf.ParseConfigurationFile(this.pathInputFile);

      Assert.IsTrue(Config.MappingsHostWildcards.Count == 0);
      Assert.IsTrue(Config.MappingsHostname.Count == 2);
    }



    [TestMethod]
    public void HostRegex_Find()
    {
      File.AppendAllText(this.pathInputFile, $"*oogle.c*||www.altavista.com{Environment.NewLine}*20min.ch||watson.ch");
      var conf = new Config();
      var reqObj = this.GenerateBasicRequest("http", "www.google.com");
      var pluginHostMapping = new HttpReverseProxy.Plugin.HostMapping.HostMapping();
      pluginHostMapping.PluginProperties.PluginHost = this.GeneratePluginHost();
      conf.ParseConfigurationFile(this.pathInputFile);
      pluginHostMapping.OnPostClientHeadersRequest(reqObj);

      Assert.IsTrue(Config.MappingsHostWildcards.Count == 2);
      Assert.IsTrue(reqObj.ClientRequestObj.Host == "www.altavista.com");
      Assert.IsTrue(reqObj.ClientRequestObj.ClientRequestHeaders["Host"][0] == "www.altavista.com");
    }

    #region PRIVATE

    private RequestObj GenerateBasicRequest(string scheme, string host)
    {
      var reqObj = new RequestObj("minary.io", ProxyProtocol.Http);
      reqObj.ClientRequestObj.Scheme = scheme;
      reqObj.ClientRequestObj.Host = host;
      reqObj.ClientRequestObj.ClientRequestHeaders = new Dictionary<string, List<string>>() { { "Host", new List<string>() { host } } };

      return reqObj;
    }


    private IPluginHost GeneratePluginHost()
    {
      IPluginHost retVal = new PluginHost();

      return retVal;
    }


    private class PluginHost : IPluginHost
    {
      public Logging LoggingInst { get; set; }

      public void RegisterPlugin(IPlugin pluginData)
      {
        //throw new NotImplementedException();
      }

      public PluginHost()
      {
        this.LoggingInst = HttpReverseProxyLib.Logging.Instance;
      }
    }

    #endregion


  }

}
