namespace HttpReverseProxyLib.Interface
{
  using System;
  using System.IO;
  using System.Text.RegularExpressions;


  public abstract class HttpReverseProxyBasis
  {

    #region PUBLIC

    public void CreateCertificate(string certificateHost)
    {
      Console.WriteLine("Creating new certificate for {0} {1}", Directory.GetCurrentDirectory(), certificateHost);
      string certificateFileName = Regex.Replace(certificateHost, @"[^\d\w_]", "_");
      string certificateOutputPath = string.Format("{0}.pfx", certificateFileName);
      DateTime validityStartDate = DateTime.Now.AddDays(-1);
      DateTime validityEndDate = DateTime.Now.AddYears(5);

      // Delete certificate file if it already exists
      if (File.Exists(certificateOutputPath))
      {
        Console.WriteLine("Certificate file \"{0}\" already exists. You have to (re)move the file in order to create a new certificate.", certificateOutputPath);
        return;
      }

      // Create certificate
      NativeWindowsLib.Crypto.Crypto.CreateNewCertificate(certificateOutputPath, certificateHost, validityStartDate, validityEndDate);
      Console.WriteLine("Certificate created successfully.");
      Console.WriteLine("Certificate file: {0}", certificateOutputPath);
      Console.WriteLine("Certificate validity start: {0}", validityStartDate);
      Console.WriteLine("Certificate validity end: {0}", validityEndDate);
    }

    #endregion


    #region ABSTRACT METHODS

    public abstract bool Start(int localServerPort, string certificatePath);

    public abstract void Stop();

    #endregion

  }
}
