package kaiju.tools.ghihorn.tools;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Common events that tools must implement
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface GhiHornEventConfig {

    String completeUpdate() default "";
    
    String cancelUpdate() default "";

    String statusUpdate() default "";

    String resultUpdate() default "";
}
