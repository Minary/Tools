using HttpReverseProxy.Plugin.InjectFile;
using HttpReverseProxyLib.DataTypes;
using HttpReverseProxyLib.DataTypes.Enum;
using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TestsPlugins;

namespace TestsPluginsHostmapping
{

  [TestClass]
  public class InjectFile
  {

    #region MEMBERS

    private string tempInputFilePath;
    private string injectFilePath = @"c:\temp\file_inject.txt";
    private string injectFileData = "INJECTED_FILE_DATA";

    #endregion


    #region (DE)INIT

    [TestInitialize]
    public void TestInit()
    {
      this.tempInputFilePath = Path.GetTempFileName();

      if (File.Exists(this.injectFilePath) == false)
      {
        File.AppendAllText(this.injectFilePath, this.injectFileData);
      }
    }


    [TestCleanup]
    public void TestClean()
    {
      TestsPlugins.HelperMethods.Inst.RemoveFile(this.tempInputFilePath);
      TestsPlugins.HelperMethods.Inst.RemoveFile(this.injectFilePath);
    }

    #endregion


    // *google.c*||/path/to/file*.php||c:\tmp\injectfile.jpg
    [TestMethod]
    public void InjectFile_LoadConfig_Wildcard()
    {
      File.AppendAllText(this.tempInputFilePath, $@"*google.c*||/dir/file*.php||{this.injectFilePath}");
      var conf = new Config();
      conf.ParseConfigurationFile(this.tempInputFilePath);

      Assert.IsTrue(Config.InjectFileRecords.Count == 1);
    }


    [TestMethod]
    public void Inject_file_success()
    {
      File.AppendAllText(this.tempInputFilePath, $@"*google.c*||/path/to/file*.php||{this.injectFilePath}");
      var conf = new Config();
      var reqObj = TestsPlugins.HelperMethods.Inst.GenerateBasicRequest("http", "www.google.com", "/path/to/file/random.php");
      var pluginInjectFile = new HttpReverseProxy.Plugin.InjectFile.InjectFile();
      pluginInjectFile.PluginProperties.PluginHost = HelperMethods.Inst.GeneratePluginHost();
      conf.ParseConfigurationFile(this.tempInputFilePath);
      PluginInstruction instr = pluginInjectFile.OnPostClientHeadersRequest(reqObj);

      Assert.IsTrue(Config.InjectFileRecords.Count == 1);
      Assert.IsTrue(instr.Instruction == Instruction.SendBackLocalFile);
      Assert.IsTrue(instr.InstructionParameters.Data == injectFilePath);
    }


    [TestMethod]
    public void Inject_file_no()
    {
      File.AppendAllText(this.tempInputFilePath, $@"*google.c*||/path/to/file*.php||{this.injectFilePath}");
      var conf = new Config();
      var reqObj = TestsPlugins.HelperMethods.Inst.GenerateBasicRequest("http", "www.google.com", "/path/to/file/random.php");
      var pluginInjectFile = new HttpReverseProxy.Plugin.InjectFile.InjectFile();
      pluginInjectFile.PluginProperties.PluginHost = HelperMethods.Inst.GeneratePluginHost();
      conf.ParseConfigurationFile(this.tempInputFilePath);
      PluginInstruction instr = pluginInjectFile.OnPostClientHeadersRequest(reqObj);

      Assert.IsTrue(Config.InjectFileRecords.Count == 1);
      Assert.IsTrue(instr.Instruction == Instruction.SendBackLocalFile);
      Assert.IsTrue(instr.InstructionParameters.Data == injectFilePath);
    }

  }
}
