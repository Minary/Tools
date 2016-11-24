namespace HttpReverseProxyLib.Exceptions
{
  using System;

  public class ProxyWarningException : Exception
  {

    public ProxyWarningException(string message) :
      base(message)
    {
    }
  }
}
