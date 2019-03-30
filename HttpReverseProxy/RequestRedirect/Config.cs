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

      var configFileLines = File.ReadAllLines(configFilePath);
      RequestRedirectRecords.Clear();

      foreach (var tmpLine in configFileLines)
      {
        try
        {
          RequestRedirectConfigRecord newRecord = this.VerifyRecordParameters(tmpLine);

          // Make regex from hostname/path
          newRecord.HostnameStr = this.RegexifyHostname(newRecord.HostnameStr);
          newRecord.HostnameRegex = new Regex(newRecord.HostnameStr, RegexOptions.Compiled | RegexOptions.IgnoreCase);
          newRecord.PathStr = this.RegexifyPath(newRecord.PathStr);
          newRecord.PathRegex = new Regex(newRecord.PathStr, RegexOptions.Compiled | RegexOptions.IgnoreCase);

          RequestRedirectRecords.Add(newRecord);
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


    protected RequestRedirectConfigRecord VerifyRecordParameters(string configFileLine)
    {
      var redirectType = string.Empty;
      var redirectDescription = string.Empty;
      var hostname = string.Empty;
      var path = string.Empty;
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
      hostname = splitter[2].ToLower();
      path = splitter[3];
      replacementResource = splitter[4];

      if (string.IsNullOrEmpty(redirectType))
      {
        throw new ProxyWarningException("The redirect type is invalid");
      }

      if(string.IsNullOrEmpty(redirectDescription))
      {
        throw new ProxyWarningException("The redirect description is invalid");
      }

      if (string.IsNullOrEmpty(hostname) == true)
      {
        throw new ProxyWarningException($"The host parameter is invalid: {hostname}");
      }

      if (string.IsNullOrEmpty(path) == true)
      {
        throw new ProxyWarningException($"The path parameter is invalid: {path}");
      }

      if (string.IsNullOrEmpty(replacementResource))
      {
        throw new ProxyWarningException($"The replacement resource parameter is invalid: {replacementResource}");
      }

      if (RequestRedirectRecords.Exists(elem => elem.HostnameStr == hostname && elem.PathStr == path))
      {
        throw new ProxyWarningException("Record already exists");
      }

      return new RequestRedirectConfigRecord(redirectType, redirectDescription, hostname, path, replacementResource);
    }

    #endregion

  }
}
