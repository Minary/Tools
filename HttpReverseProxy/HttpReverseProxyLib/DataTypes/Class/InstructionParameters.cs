namespace HttpReverseProxyLib.DataTypes.Class
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using System.Collections.Generic;


  public class InstructionParams
  {
    
    #region PROPERTIES

    public Instruction Instruction { get; set; }

    public string Url { get; set; }

    public string Status { get; set; }

    public string StatusDescription { get; set; }

    public string Data { get; set; }

    public string Data2 { get; set; }

    public Dictionary<string, string> DataDict { get; set; } = new Dictionary<string, string>();

    public List<string> HttpHeaders { get; set; }

    #endregion

  }
}
