using HttpReverseProxy.Plugin.HostMapping;
using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TestsPlugins;


namespace TestsPluginsHostmapping
{

  [TestClass]
  public class HostMapping
  {

    #region MEMBERS

    private string pathInputFile;

    #endregion


    #region (DE)INIT

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
          Console.WriteLine($"TestClean(EXC): {ex.Message}");
        }
      }
    }

    #endregion


    [TestMethod]
    public void HostMapping_LoadConfig_Wildcard()
    {
      File.AppendAllText(this.pathInputFile, "*oogle.c*||www.altavista.com");
      var conf = new Config();
      conf.ParseConfigurationFile(this.pathInputFile);

      Assert.IsTrue(Config.MappingsHostWildcards.Count == 1);
      Assert.IsTrue(Config.MappingsHostname.Count == 0);
    }


    [TestMethod]
    public void HostMapping_LoadConfig_FixHostname()
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
      var reqObj = HelperMethods.Inst.GenerateBasicRequest("http", "www.google.com", "/");
      var pluginHostMapping = new HttpReverseProxy.Plugin.HostMapping.HostMapping();
      pluginHostMapping.PluginProperties.PluginHost = HelperMethods.Inst.GeneratePluginHost();
      conf.ParseConfigurationFile(this.pathInputFile);
      pluginHostMapping.OnPostClientHeadersRequest(reqObj);

      Assert.IsTrue(Config.MappingsHostWildcards.Count == 2);
      Assert.IsTrue(reqObj.ClientRequestObj.Host == "www.altavista.com");
      Assert.IsTrue(reqObj.ClientRequestObj.ClientRequestHeaders["Host"][0] == "www.altavista.com");
    }

    
  } 
}
