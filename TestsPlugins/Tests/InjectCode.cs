using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using HttpReverseProxy.Plugin.InjectCode;


namespace TestsPluginsHostmapping
{

  [TestClass]
  public class InjectCode
  {

    #region MEMBERS

    private string tempInputFilePath;
    private string injectFilePath = @"c:\temp\code_inject.txt";
    private string injectFileData = "<inject>...</inject>";

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

    // body||after||C:\tmp\la.txt||www.spin.ch||/honk.html
    // html||after||C:\tmp\la.txt||*google.c*||/dir/file*.php
    [TestMethod]
    public void InjectCode_LoadConfig_Wildcard()
    {
      File.AppendAllText(this.tempInputFilePath, $@"html||after||{this.injectFilePath}||*google.c*||/dir/file*.php");
      var conf = new Config();
      conf.ParseConfigurationFile(this.tempInputFilePath);
      
      Assert.IsTrue(Config.InjectCodeRecords.Count == 1);
    }


    [TestMethod]
    public void InjectCode_After_BODY_success()
    {
      File.AppendAllText(this.tempInputFilePath, $@"body||after||{this.injectFilePath}||*google.c*||/dir/file*.php");
      var conf = new Config();
      var requestObj = TestsPlugins.HelperMethods.Inst.GenerateBasicRequest("http", "www.google.com", "/dir/file/random.php");
      var dataChunk = TestsPlugins.HelperMethods.Inst.GenerateDataChunk();
      var pluginObj = new HttpReverseProxy.Plugin.InjectCode.InjectCode();

      conf.ParseConfigurationFile(this.tempInputFilePath);
      pluginObj.OnServerDataTransfer(requestObj, dataChunk);
      var responseStr = System.Text.Encoding.ASCII.GetString(dataChunk.ContentData);

      Assert.IsTrue(Config.InjectCodeRecords.Count == 1);
      Assert.IsNotNull(responseStr);
      Assert.IsTrue(responseStr.ToLower().Contains(injectFileData));
    }


    [TestMethod]
    public void InjectCode_no_match()
    {
      File.AppendAllText(this.tempInputFilePath, $@"body||after||{this.injectFilePath}||*google.c*||/dir/file*.php");
      var conf = new Config();
      var requestObj = TestsPlugins.HelperMethods.Inst.GenerateBasicRequest("http", "www.google.com", "/dir/random.php");
      var dataChunk = TestsPlugins.HelperMethods.Inst.GenerateDataChunk();
      var pluginObj = new HttpReverseProxy.Plugin.InjectCode.InjectCode();

      conf.ParseConfigurationFile(this.tempInputFilePath);
      pluginObj.OnServerDataTransfer(requestObj, dataChunk);
      var responseStr = System.Text.Encoding.ASCII.GetString(dataChunk.ContentData);

      Assert.IsTrue(Config.InjectCodeRecords.Count == 1);
      Assert.IsNotNull(responseStr);
      Assert.IsFalse(responseStr.ToLower().Contains(injectFileData));
    }

  }
}
