namespace HttpReverseProxy.Plugin.RequestRedirect
{
  using HttpReverseProxy.Plugin.RequestRedirect.DataTypes;
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using System.Collections.Generic;
  using System.IO;
  using System.Text.RegularExpressions;


  public class Config
  {
    
    #region PROPERTIES

    public static string PluginName { get; private set; } = "RequestRedirect";

    public static int PluginPriority { get; private set; } = 3;

    public static string ConfigFileName { get; private set; } = "plugin.config";

    public static string PluginVersion { get; private set; } = "0.1";

    public static List<RequestRedirectConfigRecord> RequestRedirectRecords { get; set; } = new List<RequestRedirectConfigRecord>();

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
      RequestRedirectRecords.Clear();

      foreach (string tmpLine in configFileLines)
      {
        try
        {
          RequestRedirectRecords.Add(this.VerifyRecordParameters(tmpLine));
        }
        catch (ProxyWarningException pwex)
        {
          Logging.Instance.LogMessage("CONFIG", ProxyProtocol.Undefined, Loglevel.Debug, @"RequestRedirect.VerifyRecordParameters(EXCEPTION) : {0}", pwex.Message);
        }
        catch (ProxyErrorException peex)
        {
          Logging.Instance.LogMessage("CONFIG", ProxyProtocol.Undefined, Loglevel.Debug, @"RequestRedirect.VerifyRecordParameters(EXCEPTION) : {0}", peex.Message);
        }
      }
    }

    #endregion


    #region PROTECTED

    protected RequestRedirectConfigRecord VerifyRecordParameters(string configFileLine)
    {
      var redirectType = string.Empty;
      var redirectDescription = string.Empty;
      var hostRegex = string.Empty;
      var pathRegex = string.Empty;
      var replacementResource = string.Empty;

      if (string.IsNullOrEmpty(configFileLine))
      {
        throw new ProxyWarningException("Configuration line is invalid");
      }

      var splitter = Regex.Split(configFileLine, @"\|\|");
      if (splitter.Length != 5)
      {
        throw new ProxyWarningException("Wrong numbers of configuration parameters");
      }

      redirectType = splitter[0];
      redirectDescription = splitter[1];
      hostRegex = splitter[2].ToLower();
      pathRegex = splitter[3];
      replacementResource = splitter[4];

      if (string.IsNullOrEmpty(redirectType))
      {
        throw new ProxyWarningException("The redirect type is invalid");
      }

      if(string.IsNullOrEmpty(redirectDescription))
      {
        throw new ProxyWarningException("The redirect description is invalid");
      }

      if (string.IsNullOrEmpty(hostRegex) || this.IsRegexPatternValid(hostRegex) == false)
      {
        throw new ProxyWarningException($"The host parameter is invalid: {hostRegex}");
      }

      if (string.IsNullOrEmpty(pathRegex) || this.IsRegexPatternValid(pathRegex) == false)
      {
        throw new ProxyWarningException($"The path parameter is invalid: {pathRegex}");
      }

      if (string.IsNullOrEmpty(replacementResource))
      {
        throw new ProxyWarningException($"The replacement resource parameter is invalid: {replacementResource}");
      }

      if (RequestRedirectRecords.Exists(elem => elem.HostRegex == hostRegex && elem.PathRegex == pathRegex))
      {
        throw new ProxyWarningException("Record already exists");
      }

      return new RequestRedirectConfigRecord(redirectType, redirectDescription, hostRegex, pathRegex, replacementResource);
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