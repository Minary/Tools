namespace HttpReverseProxyLib.Exceptions
{
  using System;

  public enum StatusCodeLabel
  {
    StatusCode
  }


  public class ClientNotificationException : Exception
  {
    public ClientNotificationException()
      : base()
    {
    }

    public ClientNotificationException(string message)
      : base(message)
    {
    }
  }
}
