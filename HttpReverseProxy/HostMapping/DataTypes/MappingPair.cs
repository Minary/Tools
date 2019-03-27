namespace HttpReverseProxy.Plugin.HostMapping.DataTypes
{
  using System.Text.RegularExpressions;


  public class MappingPair
  {

    #region PROPERTIES

    public Regex PatternReg;

    public string PatternStr;

    #endregion


    #region PUBLIC

    public MappingPair(Regex patternReg, string patternStr)
    {
      this.PatternReg = patternReg;
      this.PatternStr = patternStr;
    }

    #endregion

  }
}
