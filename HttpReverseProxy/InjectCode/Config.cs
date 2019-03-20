namespace HttpReverseProxy.Plugin.InjectCode
{
  using HttpReverseProxy.Plugin.InjectCode.DataTypes;
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using System.Collections.Generic;
  using System.IO;
  using System.Linq;
  using System.Text.RegularExpressions;


  public class Config
  {

    #region PROPERTIES

    public static string PluginName { get; private set; } = "InjectCode";

    public static int PluginPriority { get; private set; } = 5;

    public static string ConfigFileName { get; private set; } = "plugin.config";

    public static string PluginVersion { get; private set; } = "0.1";

    public static List<InjectCodeConfigRecord> InjectCodeRecords { get; set; } = new List<InjectCodeConfigRecord>();

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

      var configFileLines = File.ReadAllLines(configFilePath);
      InjectCodeRecords.Clear();
      
      foreach (var tmpLine in configFileLines)
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
          InjectCodeRecords.Add(newRecord);
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
      var hostRegex = string.Empty;
      var pathRegex = string.Empty;
      var fileContent = string.Empty;
      var injectionCodeFile = string.Empty;
      var tag = string.Empty;
      var tagRegex = string.Empty;
      var position = TagPosition.before;

      if (string.IsNullOrEmpty(configFileLine))
      {
        throw new ProxyWarningException("Configuration line is invalid");
      }
      
      var splitter = Regex.Split(configFileLine, @"\|\|");
      if (splitter.Length != 5)
      {
        throw new ProxyWarningException("Wrong numbers of configuration parameters");
      }
      
      tag = splitter[0];
      position = splitter[1].ToLower().Trim() == "before" ? TagPosition.before : TagPosition.after;
      injectionCodeFile = splitter[2];
      hostRegex = splitter[3]?.ToLower();
      pathRegex = splitter[4];

      if (string.IsNullOrEmpty(hostRegex) || this.IsRegexPatternValid(hostRegex) == false)
      {
        throw new ProxyWarningException($"Host parameter is invalid: {hostRegex}");
      }

      if (string.IsNullOrEmpty(pathRegex) || this.IsRegexPatternValid(pathRegex) == false)
      {
        throw new ProxyWarningException($"Path parameter is invalid: {pathRegex}");
      }

      if (string.IsNullOrEmpty(injectionCodeFile) || !File.Exists(injectionCodeFile))
      {
        throw new ProxyWarningException($"The injection code file parameter is invalid: {injectionCodeFile}");
      }

      if (InjectCodeRecords.Where(elem => elem.HostRegex.ToLower() == hostRegex.ToLower() &&
                                          elem.PathRegex.ToLower() == pathRegex.ToLower()).ToList().Count > 0)
      {
        throw new ProxyWarningException("Record already exists");
      }

      return new InjectCodeConfigRecord(hostRegex, pathRegex, injectionCodeFile, tag, position);
    }


    public bool IsRegexPatternValid(string pattern)
    {
      var isValid = false;

      try
      {
        new Regex(pattern);
        isValid = true;
      }
      catch
      {
      }

      return isValid;
    }

    #endregion

  }
}
