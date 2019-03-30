namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxy.Plugin.HostMapping.DataTypes;
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

    public static Dictionary<string, MappingPair> MappingsHostWildcards { get; set; } = new Dictionary<string, MappingPair>();

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
      MappingsHostname.Clear();
      MappingsHostWildcards.Clear();

      foreach (string tmpLine in configFileLines)
      {
        if (string.IsNullOrEmpty(tmpLine) ||
            tmpLine.Contains("||") == false)
        {
          continue;
        }

        // Data structure is: RequestedHost||MappedHost
        string[] splitter = Regex.Split(tmpLine, @"\|\|");
        if (splitter.Length != 2)
        {
          continue;
        }

        // If host name starts WITH an asterisk (*) 
        // save it as wildcard host mapping.
        // The host name characters are escaped (because of the . character) and 
        // all asterisks are replaced by Regex /[^\.]+/
        if (splitter[0].Contains("*") == true)
        {
          var tmpRegex = splitter[0].Replace("*", "ASTERISK");
          tmpRegex = Regex.Escape(tmpRegex);
          tmpRegex = tmpRegex.Replace("ASTERISK", @"[\d\w\-_\.]+?");
          var compRegex = new Regex(tmpRegex, RegexOptions.Compiled|RegexOptions.IgnoreCase);
          MappingsHostWildcards.Add(splitter[1], new MappingPair(compRegex, splitter[0]));

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
