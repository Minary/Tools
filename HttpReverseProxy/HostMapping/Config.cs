namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib.Exceptions;
  using System.Collections.Generic;
  using System.IO;
  using System.Text.RegularExpressions;


  public class Config
  {
    
    #region PROPERTIES

    public static string PluginName { get; private set; } = "HostMapping";

    public static int PluginPriority { get; private set; } = 1;

    public static string PluginVersion { get; private set; } = "0.1";

    public static string ConfigFileName { get; private set; } = "plugin.config";

    public static Dictionary<string, string> MappingsHostname { get; set; } = new Dictionary<string, string>();

    public static Dictionary<string, string> MappingsHostWildcards { get; set; } = new Dictionary<string, string>();

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
      foreach (string tmpLine in configFileLines)
      {
        if (string.IsNullOrEmpty(tmpLine) ||
            tmpLine.Contains("||") == false)
        {
          continue;
        }

        // Data structure is: RequestedHost:MappedHost
        string[] splitter = Regex.Split(tmpLine, @"\|\|");
        if (splitter.Length != 2)
        {
          continue;
        }

        // If host name starts with an asterisk (*) 
        // save it as wildcard host mapping.
        // The host name characters are escaped (the . character) and 
        // all asterisks are replaced by Regex /[^\.]{1}/
        if (splitter[0].StartsWith("*") == true)
        {
          var hostnameEnding = splitter[0].Replace("*", "");
          MappingsHostWildcards.Add(hostnameEnding.ToLower(),  splitter[1]);

        // If hostname does not contain any asterisk (*) characters
        // save it as a regular host mapping
        }
        else if (!MappingsHostname.ContainsKey(splitter[0]))
        {
          MappingsHostname.Add(splitter[0].ToLower(),  splitter[1]);
        }
      }
    }

    #endregion

  }
}