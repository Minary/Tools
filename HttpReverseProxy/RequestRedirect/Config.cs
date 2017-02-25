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
      string host = string.Empty;
      string path = string.Empty;
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
      host = splitter[2].ToLower();
      path = splitter[3];
      replacementResource = splitter[4];

      if (string.IsNullOrEmpty(host) || !Regex.Match(host, @"[\d\w_\-\.]").Success)
      {
        throw new ProxyWarningException(string.Format("Host parameter is invalid: {0}", host));
      }

      if (string.IsNullOrEmpty(path) || Regex.Match(host, @"[\r\n\s]").Success)
      {
        throw new ProxyWarningException(string.Format("Path parameter is invalid: {0}", path));
      }

      if (string.IsNullOrEmpty(replacementResource) || Regex.Match(host, @"[\r\n\s]").Success)
      {
        throw new ProxyWarningException(string.Format("Replacement resource parameter is invalid: {0}", replacementResource));
      }

      if (requestRedirectRecords.Exists(elem => elem.Host == host && elem.Path == path))
      {
        throw new ProxyWarningException(string.Format("Record already exists"));
      }

      return new RequestRedirectConfigRecord(redirectType, redirectDescription, host, path, replacementResource);
    }

    #endregion

  }
}