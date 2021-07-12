package kaiju.tools.ghihorn.tools.pathanalyzer;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import kaiju.tools.ghihorn.tools.GhiHornEventConfig;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface PathAnalyzerConfig {
    GhiHornEventConfig events();

    String startAddress() default "";

    String endAddress() default "";
}
