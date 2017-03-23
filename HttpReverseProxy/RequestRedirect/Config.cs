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

    #region MEMBERS

    private static string pluginName = "RequestRedirect";
    private static int pluginPriority = 3;
    private static string pluginVersion = "0.1";
    private static string configFileName = "plugin.config";

    private static List<RequestRedirectConfigRecord> requestRedirectRecords = new List<RequestRedirectConfigRecord>();

    #endregion


    #region PROPERTIES

    public static string PluginName { get { return pluginName; } set { } }

    public static int PluginPriority { get { return pluginPriority; } set { } }

    public static string ConfigFileName { get { return configFileName; } set { } }

    public static string PluginVersion { get { return pluginVersion; } set { } }

    public static List<RequestRedirectConfigRecord> RequestRedirectRecords { get { return requestRedirectRecords; } set { } }

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
      requestRedirectRecords.Clear();

      foreach (string tmpLine in configFileLines)
      {
        try
        {
          requestRedirectRecords.Add(this.VerifyRecordParameters(tmpLine));
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
      string redirectType = string.Empty;
      string redirectDescription = string.Empty;
      string hostRegex = string.Empty;
      string pathRegex = string.Empty;
      string replacementResource = string.Empty;

      if (string.IsNullOrEmpty(configFileLine))
      {
        throw new ProxyWarningException("Configuration line is invalid");
      }

      string[] splitter = Regex.Split(configFileLine, @"\|\|");
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
        throw new ProxyWarningException(string.Format("The host parameter is invalid: {0}", hostRegex));
      }

      if (string.IsNullOrEmpty(pathRegex) || this.IsRegexPatternValid(pathRegex) == false)
      {
        throw new ProxyWarningException(string.Format("The path parameter is invalid: {0}", pathRegex));
      }

      if (string.IsNullOrEmpty(replacementResource))
      {
        throw new ProxyWarningException(string.Format("The replacement resource parameter is invalid: {0}", replacementResource));
      }

      if (requestRedirectRecords.Exists(elem => elem.HostRegex == hostRegex && elem.PathRegex == pathRegex))
      {
        throw new ProxyWarningException(string.Format("Record already exists"));
      }

      return new RequestRedirectConfigRecord(redirectType, redirectDescription, hostRegex, pathRegex, replacementResource);
    }


    public bool IsRegexPatternValid(string pattern)
    {
      bool isValid = false;

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