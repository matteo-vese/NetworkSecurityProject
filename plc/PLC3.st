PROGRAM PLC3
  VAR
    level AT %IW0 : INT;
    pump AT %QX0.0 : BOOL;
    low AT %QX0.2 : BOOL;
    high AT %QX0.1 : BOOL;
    low_3 AT %MW0 : INT := 0;
    high_3 AT %MW1 : INT := 10;
  END_VAR
  VAR
    LE13_OUT : BOOL;
    GE12_OUT : BOOL;
  END_VAR

  LE13_OUT := LE(level, low_3);
  low := LE13_OUT;
  GE12_OUT := GE(level, high_3);
  high := GE12_OUT;
  pump := NOT(low) AND (high OR pump);
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : PLC3;
  END_RESOURCE
END_CONFIGURATION