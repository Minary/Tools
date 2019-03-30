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

    public static string PluginVersion { get; private set; } = "0.1";

    public static string ConfigFileName { get; private set; } = "plugin.config";

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
        if (string.IsNullOrEmpty(tmpLine) ||
            tmpLine.Contains("||") == false)
        {
          continue;
        }
        
        try
        {
          InjectCodeConfigRecord newRecord = this.VerifyRecordParameters(tmpLine);

          // Make regex from hostname/path
          newRecord.HostnameStr = this.RegexifyHostname(newRecord.HostnameStr);
          newRecord.HostnameRegex = new Regex(newRecord.HostnameStr, RegexOptions.Compiled | RegexOptions.IgnoreCase);
          newRecord.PathStr = this.RegexifyPath(newRecord.PathStr);
          newRecord.PathRegex = new Regex(newRecord.PathStr, RegexOptions.Compiled | RegexOptions.IgnoreCase);

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

    private string RegexifyHostname(string wildcardBuffer)
    {
      if (string.IsNullOrEmpty(wildcardBuffer) ||
          wildcardBuffer.Contains("*") == false)
      {
        return wildcardBuffer;
      }

      var tmpRegex = wildcardBuffer.Replace("*", "ASTERISK");
      tmpRegex = Regex.Escape(tmpRegex);
      wildcardBuffer = tmpRegex.Replace("ASTERISK", @"[\d\w\-_\.]*?");

      return wildcardBuffer;
    }


    private string RegexifyPath(string wildcardBuffer)
    {
      if (string.IsNullOrEmpty(wildcardBuffer) ||
          wildcardBuffer.Contains("*") == false)
      {
        return wildcardBuffer;
      }

      var tmpRegex = wildcardBuffer.Replace("*", "ASTERISK");
      tmpRegex = Regex.Escape(tmpRegex);
      wildcardBuffer = tmpRegex.Replace("ASTERISK", @"[\d\w\-_\/\.\+\~\=\&\?]*?");

      return wildcardBuffer;
    }


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

      if (string.IsNullOrEmpty(hostRegex))
      {
        throw new ProxyWarningException($"Host parameter is invalid: {hostRegex}");
      }

      if (string.IsNullOrEmpty(pathRegex))
      {
        throw new ProxyWarningException($"Path parameter is invalid: {pathRegex}");
      }

      if (string.IsNullOrEmpty(injectionCodeFile) ||
          !File.Exists(injectionCodeFile))
      {
        throw new ProxyWarningException($"The injection code file parameter is invalid: {injectionCodeFile}");
      }

      if (InjectCodeRecords.Where(elem => elem.HostnameStr.ToLower() == hostRegex.ToLower() &&
                                          elem.PathStr.ToLower() == pathRegex.ToLower()).ToList().Count > 0)
      {
        throw new ProxyWarningException("Record already exists");
      }

      return new InjectCodeConfigRecord(hostRegex, pathRegex, injectionCodeFile, tag, position);
    }

    #endregion

  }
}




