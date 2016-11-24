namespace HttpReverseProxyLib
{
  using System;
  using System.Collections.Generic;
  using System.IO;
  using System.Text.RegularExpressions;

  public class Logging
  {

    #region MEMBERS

    private static Logging instance;
    private static StreamWriter logFileStreamWriter;
    private static string logfilePath;
    private static string logFileName = "HttpProxy.log";
    private object syncObj = new object();
    private List<string> logs = new List<string>();
    private Logging.Level logLevel;
    private bool isInTestingMode;

    #endregion


    #region TYPE DEFINITIONS

    public enum Level : int
    {
      DEBUG = 1,
      INFO = 2,
      WARNING = 3,
      ERROR = 4
    }

    #endregion


    #region PROPERTIES

    public static Logging Instance { get { return instance ?? (instance = GetInstance()); } set { } }
    public Logging.Level LoggingLevel { get { return this.logLevel; } set { this.logLevel = value; } }
    public bool IsInTestingMode { get { return this.isInTestingMode; } set { this.isInTestingMode = value; } }

    #endregion


    #region PUBLIC

    /// <summary>
    ///
    /// </summary>
    /// <param name="reqObj"></param>
    /// <param name="message"></param>
    /// <param name="logLevel"></param>
    public void LogMessage(string requestId, Level logLevel, string message, params object[] messageParams)
    {
      if (string.IsNullOrEmpty(message) || string.IsNullOrWhiteSpace(message))
      {
        return;
      }

      if (logLevel < this.logLevel)
      {
        return;
      }

      if (requestId == null || string.IsNullOrEmpty(requestId))
      {
        requestId = "UNDEF";
      }

      try
      {
        // Prepare log message
        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        if (messageParams != null && messageParams.Length > 0)
        {
          message = string.Format(message, messageParams);
        }

        message = message.Trim();

        lock (syncObj)
        {
          logFileStreamWriter.WriteLine("{0} {1}: {2}", timestamp, requestId, message);
          logFileStreamWriter.Flush();
          logFileStreamWriter.BaseStream.Flush();

Console.WriteLine("{0} {1}: {2}", timestamp, requestId, message);
          // If testing this application add record to array
          if (this.isInTestingMode)
          {
            string logLine = string.Format("{0} {1}: {2}{3}", timestamp, requestId, message, Environment.NewLine);
            logs.Add(logLine);
          }
        }
      }
      catch (Exception ex)
      {
        if (logLevel == Logging.Level.DEBUG)
        {
          Console.WriteLine("ERROR: Error occurred in LogMessage: {0}", ex.Message);
        }
      }
    }

    /// <summary>
    ///
    /// </summary>
    /// <param name="searchPattern"></param>
    /// <returns></returns>
    public List<string> FindLogRecordByRegex(string searchPattern)
    {
      List<string> foundLogRecords = new List<string>();

      foreach (string tmpLogRecord in logs)
        if (Regex.Match(tmpLogRecord, searchPattern, RegexOptions.IgnoreCase).Success)
        {
          foundLogRecords.Add(tmpLogRecord);
        }

      return foundLogRecords;
    }


    public void DumpLogRecords()
    {
      foreach (string tmpLogRecord in logs)
      {
        Console.WriteLine("LOG: {0}", tmpLogRecord.Trim());
      }
    }


    /// <summary>
    ///
    /// </summary>
    public void ResetLogging()
    {
      logs.Clear();
    }

    #endregion


    #region PRIVATE

    /// <summary>
    /// Initializes a new instance of the <see cref="Logging"/> class.
    ///
    /// </summary>
    /// <param name="logLevel"></param>
    private Logging(Logging.Level logLevel = Level.DEBUG)
    {
      this.logLevel = logLevel;
    }



    private static Logging GetInstance()
    {
      Logging instance = new Logging();

      // Close log file stream if it is still open.
      try
      {
        if (logFileStreamWriter != null)
        {
          logFileStreamWriter.Close();
        }
      }
      catch
      {
      }

      // Open log file stream
      try
      {
        logfilePath = Path.Combine(Directory.GetCurrentDirectory(), logFileName);
        logFileStreamWriter = File.AppendText(logFileName);
        logFileStreamWriter.AutoFlush = true;
      }
      catch
      {
      }

      return instance;
    }

    #endregion

  }
}
