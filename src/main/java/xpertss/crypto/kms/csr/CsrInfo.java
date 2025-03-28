package xpertss.crypto.kms.csr;

public class CsrInfo {

    private final String cn;
    private final String ou;
    private final String o;
    private final String l;
    private final String st;
    private final String c;
    private final String mail;

    private CsrInfo(Builder builder)
    {
        this.cn = builder.cn;
        this.ou = builder.ou;
        this.o = builder.o;
        this.l = builder.l;
        this.st = builder.st;
        this.c = builder.c;
        this.mail = builder.mail;
    }

    public String getCn()
    {
        return cn;
    }

    public String getOu()
    {
        return ou;
    }

    public String getO()
    {
        return o;
    }

    public String getL()
    {
        return l;
    }

    public String getSt()
    {
        return st;
    }

    public String getC()
    {
        return c;
    }

    public String getMail()
    {
        return mail;
    }


    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();

        append(builder, "CN", cn);
        append(builder, "OU", ou);
        append(builder, "O", o);
        append(builder, "L", l);
        append(builder, "ST", st);
        append(builder, "C", c);
        append(builder, "emailAddress", mail);

        return builder.toString();
    }

    private void append(StringBuilder builder, String attribute, String value)
    {
        if (value != null) {
            if (builder.length() > 0) builder.append(", ");
            builder.append(attribute).append("=").append(value);
        }
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder {

        private String cn;
        private String ou;
        private String o;
        private String l;
        private String st;
        private String c;
        private String mail;


        public Builder cn(String cn)
        {
            this.cn = cn;
            return this;
        }

        public Builder ou(String ou)
        {
            this.ou = ou;
            return this;
        }

        public Builder o(String o)
        {
            this.o = o;
            return this;
        }

        public Builder l(String l)
        {
            this.l = l;
            return this;
        }

        public Builder st(String st)
        {
            this.st = st;
            return this;
        }

        public Builder c(String c)
        {
            this.c = c;
            return this;
        }

        public Builder mail(String mail)
        {
            this.mail = mail;
            return this;
        }

        public CsrInfo build()
        {
            return new CsrInfo(this);
        }

    }


}
