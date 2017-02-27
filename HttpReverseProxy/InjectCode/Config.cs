namespace HttpReverseProxy.Plugin.InjectCode
{
  using HttpReverseProxy.Plugin.InjectCode.DataTypes;
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using System.Collections.Generic;
  using System.IO;
  using System.Text.RegularExpressions;


  public class Config
  {

    #region MEMBERS

    private static string pluginName = "InjectCode";
    private static int pluginPriority = 5;
    private static string pluginVersion = "0.1";
    private static string configFileName = "plugin.config";

    private static Dictionary<string, InjectCodeConfigRecord> injectCodeRecords = new Dictionary<string, InjectCodeConfigRecord>();

    #endregion


    #region PROPERTIES

    public static string PluginName { get { return pluginName; } set { } }

    public static int PluginPriority { get { return pluginPriority; } set { } }

    public static string ConfigFileName { get { return configFileName; } set { } }

    public static string PluginVersion { get { return pluginVersion; } set { } }

    public static Dictionary<string, InjectCodeConfigRecord> InjectCodeRecords { get { return injectCodeRecords; } set { } }

    #endregion


    #region PUBLIC

    /// <summary>
    ///
    /// </summary>
    /// <param name="configFilePath"></param>
    public void ParseConfigurationFile(string configFilePath)
    {
      if (string.IsNullOrEmpty(configFilePath))
      {
        throw new ProxyWarningException("Config file path is invalid");
      }

      if (!File.Exists(configFilePath))
      {
        throw new ProxyWarningException("Config file does not exist");
      }

      string[] configFileLines = File.ReadAllLines(configFilePath);
      injectCodeRecords.Clear();
      
      foreach (string tmpLine in configFileLines)
      {
        if (string.IsNullOrEmpty(tmpLine))
        {
          continue;
        }

        if (!tmpLine.Contains("||"))
        {
          continue;
        }

        try
        {
          InjectCodeConfigRecord newRecord = this.VerifyRecordParameters(tmpLine);
          injectCodeRecords.Add(newRecord.Host.ToLower(), newRecord);
        }
        catch (ProxyWarningException pwex)
        {
          Logging.Instance.LogMessage("CONFIG", ProxyProtocol.Undefined, Loglevel.Debug, @"InjectCode.VerifyRecordParameters(EXCEPTION) : {0}", pwex.Message);
        }
        catch (ProxyErrorException peex)
        {
          Logging.Instance.LogMessage("CONFIG", ProxyProtocol.Undefined, Loglevel.Debug, @"InjectCode.VerifyRecordParameters(EXCEPTION) : {0}", peex.Message);
        }
      }
    }

    #endregion


    #region PROTECTED

    protected InjectCodeConfigRecord VerifyRecordParameters(string configFileLine)
    {
      string host = string.Empty;
      string path = string.Empty;
      string injectionCodeFile = string.Empty;
      string tag = string.Empty;
      string position = string.Empty;

      if (string.IsNullOrEmpty(configFileLine))
      {
        throw new ProxyWarningException("Configuration line is invalid");
      }
      
      string[] splitter = Regex.Split(configFileLine, @"\|\|");

      if (splitter.Length != 5)
      {
        throw new ProxyWarningException("Wrong numbers of configuration parameters");
      }
      
      tag = splitter[0];
      position = splitter[1];
      injectionCodeFile = splitter[2];
      host = splitter[3]?.ToLower();
      path = splitter[4];

      if (string.IsNullOrEmpty(host) || !Regex.Match(host, @"[\d\w_\-\.]").Success)
      {
        throw new ProxyWarningException(string.Format("Host parameter is invalid: {0}", host));
      }

      if (string.IsNullOrEmpty(path) || Regex.Match(host, @"[\r\n\s]").Success)
      {
        throw new ProxyWarningException(string.Format("Path parameter is invalid: {0}", path));
      }

      if (string.IsNullOrEmpty(injectionCodeFile) || Regex.Match(host, @"[\r\n\s]").Success)
      {
        throw new ProxyWarningException(string.Format("The injection code file parameter is invalid: {0}", injectionCodeFile));
      }


      if (injectCodeRecords.ContainsKey(host) &&
          injectCodeRecords[host].Path == path)
      {
        throw new ProxyWarningException(string.Format("Record already exists"));
      }
      
      return new InjectCodeConfigRecord(host, path, injectionCodeFile, tag, position);
    }

    #endregion

  }
}
