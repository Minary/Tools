namespace HttpReverseProxy.Plugin.InjectFile
{
  using HttpReverseProxy.Plugin.InjectFile.DataTypes;
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using System.Collections.Generic;
  using System.IO;
  using System.Text.RegularExpressions;


  public class Config
  {

    #region PROPERTIES

    public static string PluginName { get; private set; } = "InjectFile";

    public static int PluginPriority { get; private set; } = 4;

    public static string ConfigFileName { get; private set; } = "plugin.config";

    public static string PluginVersion { get; private set; } = "0.1";

    public static List<InjectFileConfigRecord> InjectFileRecords { get; set; } = new List<InjectFileConfigRecord>();

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
      InjectFileRecords.Clear();
      foreach (var tmpLine in configFileLines)
      {
        try
        {
          InjectFileRecords.Add(this.VerifyRecordParameters(tmpLine));
        }
        catch (ProxyWarningException pwex)
        {
          Logging.Instance.LogMessage("CONFIG", ProxyProtocol.Undefined, Loglevel.Debug, @"InjectFile.VerifyRecordParameters(EXCEPTION) : {0}", pwex.Message);
        }
        catch (ProxyErrorException peex)
        {
          Logging.Instance.LogMessage("CONFIG", ProxyProtocol.Undefined, Loglevel.Debug, @"InjectFile.VerifyRecordParameters(EXCEPTION) : {0}", peex.Message);
        }
      }
    }

    #endregion


    #region PROTECTED

    protected InjectFileConfigRecord VerifyRecordParameters(string configFileLine)
    {
      var hostRegex = string.Empty;
      var pathRegex = string.Empty;
      var replacementResource = string.Empty;

      if (string.IsNullOrEmpty(configFileLine))
      {
        throw new ProxyWarningException("Configuration line is invalid");
      }

      string[] splitter = Regex.Split(configFileLine, @"\|\|");

      if (splitter.Length != 3)
      {
        throw new ProxyWarningException("Wrong numbers of configuration parameters");
      }

      hostRegex = splitter[0]?.ToLower();
      pathRegex = splitter[1];
      replacementResource = splitter[2];

      if(string.IsNullOrEmpty(hostRegex) || this.IsRegexPatternValid(hostRegex) == false)
      {
        throw new ProxyWarningException($"Host parameter is invalid: {hostRegex}");
      }

      if(string.IsNullOrEmpty(pathRegex) || this.IsRegexPatternValid(pathRegex) == false)
      {
        throw new ProxyWarningException($"Path parameter is invalid: {pathRegex}");
      }

      if (string.IsNullOrEmpty(replacementResource) || Regex.Match(hostRegex, @"[\r\n\s]").Success)
      {
        throw new ProxyWarningException($"Replacement resource parameter is invalid: {replacementResource}");
      }

      if (InjectFileRecords.Exists(elem => elem.Host == hostRegex && elem.Path == pathRegex))
      {
        throw new ProxyWarningException("Record already exists");
      }

      return new InjectFileConfigRecord(hostRegex, pathRegex, replacementResource);
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