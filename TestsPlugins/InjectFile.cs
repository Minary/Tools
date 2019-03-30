using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using HttpReverseProxy.Plugin.InjectFile;


namespace TestsPluginsHostmapping
{

  [TestClass]
  public class InjectFile
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

    // *google.c*||/path/to/file*.php||c:\tmp\injectfile.jpg
    [TestMethod]
    public void InjectFile_LoadConfig_Wildcard()
    {
      File.AppendAllText(this.tempInputFilePath, $@"*google.c*||/dir/file*.php||{this.injectFilePath}");
      var conf = new Config();
      conf.ParseConfigurationFile(this.tempInputFilePath);

      Assert.IsTrue(Config.InjectFileRecords.Count == 1);
    }

  }
}
