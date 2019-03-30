namespace HttpReverseProxy.Plugin.InjectFile
{
  using HttpReverseProxy.Plugin.InjectFile.DataTypes;
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
          InjectFileConfigRecord newRecord = this.VerifyRecordParameters(tmpLine);

          // Make regex from hostname/path
          newRecord.HostnameStr = this.RegexifyHostname(newRecord.HostnameStr);
          newRecord.HostnameRegex = new Regex(newRecord.HostnameStr, RegexOptions.Compiled | RegexOptions.IgnoreCase);
          newRecord.PathStr = this.RegexifyPath(newRecord.PathStr);
          newRecord.PathRegex = new Regex(newRecord.PathStr, RegexOptions.Compiled | RegexOptions.IgnoreCase);

          InjectFileRecords.Add(newRecord);
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


    protected InjectFileConfigRecord VerifyRecordParameters(string configFileLine)
    {
      var hostRegex = string.Empty;
      var pathRegex = string.Empty;
      var replacementResource = string.Empty;





      if (string.IsNullOrEmpty(configFileLine))
      {
        throw new ProxyWarningException("Configuration line is invalid");
      }

      var splitter = Regex.Split(configFileLine, @"\|\|");
      if (splitter.Length != 3)
      {
        throw new ProxyWarningException("Wrong numbers of configuration parameters");
      }

      hostRegex = splitter[0]?.ToLower();
      pathRegex = splitter[1];
      replacementResource = splitter[2];



      if (string.IsNullOrEmpty(hostRegex) == true)
      {
        throw new ProxyWarningException($"Host parameter is invalid: {hostRegex}");
      }

      if (string.IsNullOrEmpty(pathRegex) == true)
      {
        throw new ProxyWarningException($"Path parameter is invalid: {pathRegex}");
      }

      if (string.IsNullOrEmpty(replacementResource) == true ||
          File.Exists(replacementResource) == false)
      {
        throw new ProxyWarningException($"Replacement resource parameter is invalid: {replacementResource}");
      }

      if (InjectFileRecords.Exists(elem => elem.HostnameStr == hostRegex && 
                                           elem.PathStr == pathRegex))
      {
        throw new ProxyWarningException("Record already exists");
      }

      return new InjectFileConfigRecord(hostRegex, pathRegex, replacementResource);
    }
    
    #endregion

  }
}
