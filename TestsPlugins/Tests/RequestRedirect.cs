using HttpReverseProxy.Plugin.RequestRedirect;
using HttpReverseProxyLib.DataTypes;
using HttpReverseProxyLib.DataTypes.Enum;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TestsPlugins;


namespace TestsPluginsHostmapping
{

  [TestClass]
  public class RequestRedirect
  {

    #region MEMBERS

    private string tempInputFilePath;

    #endregion


    #region (DE)INIT

    [TestInitialize]
    public void TestInit()
    {
      this.tempInputFilePath = Path.GetTempFileName();
    }


    [TestCleanup]
    public void TestClean()
    {
      TestsPlugins.HelperMethods.Inst.RemoveFile(this.tempInputFilePath);
    }

    #endregion


    // 302||Temporary redirect||*google.c*||/path/to/file*.php||https://www.minary.io/
    [TestMethod]
    public void RequestRedirect_LoadConfig_Wildcard()
    {
      File.AppendAllText(this.tempInputFilePath, "302||Temporary redirect||*google.c*||/path/to/file*.php||https://www.minary.io/victims/hacked.php");
      var conf = new Config();
      conf.ParseConfigurationFile(this.tempInputFilePath);

      Assert.IsTrue(Config.RequestRedirectRecords.Count == 1);
    }


    [TestMethod]
    public void Request_redirect_success()
    {
      File.AppendAllText(this.tempInputFilePath, "302||Temporary redirect||*google.c*||/path/to/file*.php||https://www.minary.io/victims/hacked.php");
      var conf = new Config();
      var reqObj = TestsPlugins.HelperMethods.Inst.GenerateBasicRequest("http", "www.google.com", "/path/to/file/random.php");
      var pluginRequestRedirect = new HttpReverseProxy.Plugin.RequestRedirect.RequestRedirect();
      pluginRequestRedirect.PluginProperties.PluginHost = HelperMethods.Inst.GeneratePluginHost();
      conf.ParseConfigurationFile(this.tempInputFilePath);
      PluginInstruction instr = pluginRequestRedirect.OnPostClientHeadersRequest(reqObj);

      Assert.IsTrue(Config.RequestRedirectRecords.Count == 1);
      Assert.IsTrue(instr.Instruction == Instruction.RedirectToNewUrl);
      Assert.IsTrue(instr.InstructionParameters.Status == "302");
      Assert.IsTrue(instr.InstructionParameters.StatusDescription == "Temporary redirect");
    }


    [TestMethod]
    public void Request_redirect_no()
    {
      File.AppendAllText(this.tempInputFilePath, "302||Temporary redirect||*google.c*||/path/to/file*.php||https://www.minary.io/victims/hacked.php");
      var conf = new Config();
      var reqObj = HelperMethods.Inst.GenerateBasicRequest("http", "www.google.com", "/index.php");
      var pluginRequestRedirect = new HttpReverseProxy.Plugin.RequestRedirect.RequestRedirect();
      pluginRequestRedirect.PluginProperties.PluginHost = HelperMethods.Inst.GeneratePluginHost();
      conf.ParseConfigurationFile(this.tempInputFilePath);
      PluginInstruction instr = pluginRequestRedirect.OnPostClientHeadersRequest(reqObj);

      Assert.IsTrue(Config.RequestRedirectRecords.Count == 1);
      Assert.IsTrue(instr.Instruction == Instruction.DoNothing);
    }
  }
}
